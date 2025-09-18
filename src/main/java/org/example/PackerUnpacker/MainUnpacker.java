package org.example.PackerUnpacker;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class MainUnpacker {
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int SALT_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final byte TYPE_DIRECTORY = 0;
    private static final byte TYPE_FILE = 1;
    private static final int BUFFER_SIZE = 8192;


    private void log(String message) {
        System.out.println("[" + LocalTime.now().format(timeFormatter) + "] " + message);
    }

    public void unpack(String sourceFilePath, String destDirPath, char[] password) throws GeneralSecurityException, IOException, DataFormatException {
        File destDir = new File(destDirPath);
        if (!destDir.exists()) destDir.mkdirs();

        log("// DedSec Unpacking Protocol Initialized_");
        log("-> Analyzing payload: " + sourceFilePath);

        Inflater inflater = new Inflater();
        try (FileInputStream fis = new FileInputStream(sourceFilePath)) {
            log("// Reading security layer...");
            byte[] salt = fis.readNBytes(SALT_LENGTH);
            if (salt.length != SALT_LENGTH) throw new IOException("Archive corrupted or not a valid format.");
            SecretKey secretKey = generateSecretKey(password, salt);
            log("-> Decryption key loaded into memory.");

            log("// Beginning data extraction (Streaming + Decompression)...");

            int counter = 0;
            while (fis.available() > 0) {
                System.out.print(".");
                if (++counter % 80 == 0) System.out.println();

                int type = fis.read();
                if (type == -1) break;

                // --- FIX: Logic is now correctly separated for directories and files ---

                if (type == TYPE_DIRECTORY) {
                    int pathLength = readInt(fis);
                    byte[] pathBytes = fis.readNBytes(pathLength);
                    File outputFile = new File(destDir, new String(pathBytes, StandardCharsets.UTF_8));
                    outputFile.mkdirs(); // Just create the directory, no decryption needed.

                } else if (type == TYPE_FILE) {
                    byte[] iv = fis.readNBytes(GCM_IV_LENGTH);
                    if (iv.length != GCM_IV_LENGTH) throw new IOException("Archive format error: Invalid IV length.");

                    int pathLength = readInt(fis);
                    byte[] pathBytes = fis.readNBytes(pathLength);
                    File outputFile = new File(destDir, new String(pathBytes, StandardCharsets.UTF_8));

                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

                    outputFile.getParentFile().mkdirs();

                    int encryptedDataLength = readInt(fis);
                    byte[] encryptedData = fis.readNBytes(encryptedDataLength);
                    byte[] compressedData = cipher.doFinal(encryptedData);

                    try (FileOutputStream fos = new FileOutputStream(outputFile);
                         ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
                         InflaterInputStream iis = new InflaterInputStream(bais, inflater)) {

                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        while ((bytesRead = iis.read(buffer)) != -1) {
                            fos.write(buffer, 0, bytesRead);
                        }
                    }
                    inflater.reset();
                } else {
                    throw new IOException("Corrupted file format: unknown entry type " + type);
                }
            }
            System.out.println();
            log("// Finalizing extraction...");
            log("-> All data restored. File handles closed.");
        } finally {
            inflater.end();
        }
    }

    public List<String> listContents(String sourceFilePath, char[] password) throws IOException, GeneralSecurityException {
        List<String> contents = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(sourceFilePath)) {
            byte[] salt = fis.readNBytes(SALT_LENGTH);
            if (salt.length != SALT_LENGTH) throw new IOException("Archive corrupted or not a valid format.");
            generateSecretKey(password, salt);

            while (fis.available() > 0) {
                int type = fis.read();
                if (type == -1) break;

                int pathLength = readInt(fis);
                byte[] pathBytes = fis.readNBytes(pathLength);
                String relativePath = new String(pathBytes, StandardCharsets.UTF_8);

                if (type == TYPE_DIRECTORY) {
                    contents.add("[DIR]  " + relativePath);
                } else if (type == TYPE_FILE) {
                    contents.add("[FILE] " + relativePath);
                    fis.skip(GCM_IV_LENGTH);
                    int encryptedDataLength = readInt(fis);
                    fis.skip(encryptedDataLength);
                }
            }
        }
        return contents;
    }

    private SecretKey generateSecretKey(char[] password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private int readInt(InputStream is) throws IOException {
        int ch1 = is.read();
        int ch2 = is.read();
        int ch3 = is.read();
        int ch4 = is.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0) throw new EOFException();
        return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + ch4);
    }
}