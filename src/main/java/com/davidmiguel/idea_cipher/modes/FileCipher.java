package com.davidmiguel.idea_cipher.modes;

import com.davidmiguel.idea_cipher.modes.algorithms.CBC;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

//Codul a fost baza pe http://www.source-code.biz/idea/java
public class FileCipher extends Task<Void> {
    private static final Logger logger = LoggerFactory.getLogger(FileCipher.class);
    private static final int BLOCK_SIZE = 8;
    private String input;
    private String output;
    private String key;
    private boolean encrypt;
    private OperationMode.Mode mode;
    private StringProperty status; // To print messages in status box

    //am declarat fisierul care va fi criptat cu parametri aferenti
    public FileCipher(String input, String output, String key, boolean encrypt, OperationMode.Mode mode) {
        this.input = input;
        this.output = output;
        this.key = key;
        this.encrypt = encrypt;
        this.mode = mode;
        status = new SimpleStringProperty();
    }

    public StringProperty getStatus() {
        return status;
    }

  //Operatia de criptare si de decriptare
    private void cryptFile() throws IOException {
        // deschidem cele doua fisiere de iesire/intrare cu care vom lucra

        try (FileChannel inChannel = FileChannel.open(Paths.get(input), StandardOpenOption.READ);
             FileChannel outChannel = FileChannel.open(Paths.get(output), StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {

            // Selectam modul de operare, in cazul nostru CBC
            OperationMode opMod;
            switch (mode) {
                case CBC:
                    //Declaram un obiect avand ca si parametri modul de executie implicit si cheia pe care am introdus-o
                    opMod = new CBC(encrypt, key);
                    break;
                default:
                    //In caz de adaugare fisier gresit, afisam urmatorul mesaj
                    throw new IllegalArgumentException("Incorrect mode of operation.");
            }

            // Verificam daca fiseirul nostru are date
            long inFileSize = inChannel.size(); // Input file size (bytes)
            long inDataLen, outDataLen; // Input and output data size (bytes)
            //Daca verificarea s-a facut cu succesm adica daca fisierul are date de criptat se va face operatia de criptare
            if (encrypt) {
                inDataLen = inFileSize; // Input data size = input file size
                outDataLen = (inDataLen + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; // Closest upper multiple of blockSize
                // Daca verificarea nu s-a facut cu succes, inseamna ca fisierul este gol si se va afisa urmatorul mesaj
            } else {
                if (inFileSize == 0) {
                    throw new IOException("Input file is empty.");
                } else if (inFileSize % BLOCK_SIZE != 0) {
                    throw new IOException("Input file size is not a multiple of " + BLOCK_SIZE + ".");
                }
                inDataLen = inFileSize - BLOCK_SIZE; // Last block is the data size (encrypted)
                outDataLen = inDataLen;
            }

            // Criptare/decriptare efectiva a datelor
            long t0 = System.currentTimeMillis();
            processData(inChannel, inDataLen, outChannel, outDataLen, opMod);
            long tf = (System.currentTimeMillis() - t0);

            // Write / read lenght of the data
            if (encrypt) {
                // Add encrypted data length in an encrypted block at the end of the output file
                writeDataLength(outChannel, inDataLen, opMod);
            } else {
                // Read encrypted data length
                long dataSize = readDataLength(inChannel, opMod);
                // Check if it is coherent
                if (dataSize < 0 || dataSize > inDataLen || dataSize < inDataLen - BLOCK_SIZE + 1) {
                    throw new IOException("Input file is not a valid cryptogram (wrong file size)");
                }
                // Truncate output file to the leght of the data
                if (dataSize != outDataLen) {
                    outChannel.truncate(dataSize);
                    status.setValue("Truncating output file...");
                    logger.debug("Truncate " + outDataLen + "b to " + dataSize + "b");
                }
                status.setValue("Output size: " + dataSize / 1024 + "KB.");
            }
            status.setValue("Done!");
        }
    }

  // procesarea datelor pentru cele doua prelucrari
    private void processData(FileChannel inChannel, long inDataLen, FileChannel outChannel, long outDataLen,
                                    OperationMode opMod) throws IOException {
        final int bufSize = 0x200000; // 2MB of buffer
        ByteBuffer buf = ByteBuffer.allocate(bufSize);
        long filePos = 0;
        while (filePos < inDataLen) {
            // raportam progresul in bara de progres
            updateProgress(filePos, inDataLen);
            // Read from input file into the buffer
            int bytesToRead = (int) Math.min(inDataLen - filePos, bufSize);
            buf.limit(bytesToRead);
            buf.position(0);
            int bytesRead = inChannel.read(buf);
            if (bytesRead != bytesToRead) {
                throw new IOException("Incomplete data chunk read from file.");
            }
            // Encrypt chunk
            int chunkLen = (bytesRead + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; // Closest upper multiple of blockSize
            Arrays.fill(buf.array(), bytesRead, chunkLen, (byte) 0); // Fill the free space of the chunk with 0
            for (int pos = 0; pos < chunkLen; pos += BLOCK_SIZE) {
                opMod.crypt(buf.array(), pos); // Encrypt chunk with chosen operation mode
            }

            int bytesToWrite = (int) Math.min(outDataLen - filePos, chunkLen);
            buf.limit(bytesToWrite);
            buf.position(0);
            int bytesWritten = outChannel.write(buf);
            if (bytesWritten != bytesToWrite) {
                throw new IOException("Incomplete data chunk written to file.");
            }
            filePos += chunkLen;
        }
    }

//scriem lungimea datelor criptate într-un bloc criptat la sfârșitul fișierului.
            // Lungimea pachetului este un bloc de 8 octeți, acest bloc este criptat și adăugat în final la sfârșit
     // din fișierul de ieșire.
    private void writeDataLength(FileChannel outChannel, long dataLength, OperationMode opMod)
            throws IOException {
        // Package the dataLength into an 8-byte block
        byte[] block = packDataLength(dataLength);
        // Encrypt block
        opMod.crypt(block);
        // Write block at the end of the file
        ByteBuffer buf = ByteBuffer.wrap(block);
        int bytesWritten = outChannel.write(buf);
        if (bytesWritten != BLOCK_SIZE) {
            throw new IOException("Error while writing data length suffix.");
        }
    }


     //Obtinem lungimea datelor care au fost criptate.
     //Aceste date sunt salvate criptate în ultimul bloc al criptogramei.
     //Se citeste ultimul bloc al fișierului, il decriptam

    private long readDataLength(FileChannel channel, OperationMode opMod) throws IOException {
        // Get last block
        ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE);
        int bytesRead = channel.read(buf);
        if (bytesRead != BLOCK_SIZE) {
            throw new IOException("Unable to read data length suffix.");
        }
        byte[] block = buf.array();
        // Decrypt block
        opMod.crypt(block);
        // Unpackage data length
        return unpackDataLength(block);
    }

    /**
     * Packs 45-bit number into an 8-byte block. Used to encode the file size.
     */
    private static byte[] packDataLength(long size) {
        if (size > 0x1FFFFFFFFFFFL) { // 45 bits -> 32TB
            throw new IllegalArgumentException("File too long.");
        }
        byte[] b = new byte[BLOCK_SIZE];
        b[7] = (byte) (size << 3);
        b[6] = (byte) (size >> 5);
        b[5] = (byte) (size >> 13);
        b[4] = (byte) (size >> 21);
        b[3] = (byte) (size >> 29);
        b[2] = (byte) (size >> 37);
        return b;
    }

    /**
     * Extracts a 45-bit number from an 8-byte block. Used to decode the file size.
     * Returns -1 if the encoded value is invalid. This means that the input file is not a valid cryptogram.
     */
    private static long unpackDataLength(byte[] b) {
        if (b[0] != 0 || b[1] != 0 || (b[7] & 7) != 0) {
            return -1;
        }
        return (long) (b[7] & 0xFF) >> 3 |
                (long) (b[6] & 0xFF) << 5 |
                (long) (b[5] & 0xFF) << 13 |
                (long) (b[4] & 0xFF) << 21 |
                (long) (b[3] & 0xFF) << 29 |
                (long) (b[2] & 0xFF) << 37;
    }

    @Override
    protected Void call() throws Exception {
        updateProgress(0, 1);
        cryptFile();
        updateProgress(1, 1);
        return null;
    }
}
