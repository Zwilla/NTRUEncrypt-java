package com.securityinnovation.jNeo;

/*
 * **************************************************************************** NTRU Cryptography
 * Reference Source Code
 *
 * <p>Copyright (C) 2009-2016 Security Innovation (SI)
 * <p>Copyright (C) 2020 Zwilla Research <Michael.Padilla@zwilla.de> <LICENSE: MIT>
 *
 * <p>SI has dedicated the work to the public domain by waiving all of its rights to the work
 * worldwide under copyright law, including all related and neighboring rights, to the extent
 * allowed by law.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. You can
 * copy, modify, distribute and perform the work, even for commercial purposes, all without asking
 * permission. You should have received a copy of the creative commons license (CC0 1.0 universal)
 * along with this program. See the license file for more information.
 *
 * <p>*******************************************************************************
 */

import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.DataOutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import com.securityinnovation.jNeo.util.Random;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;

/**
 * This class is sample code for the jNeo toolkit. It supports 3 operations:
 *
 * <ul>
 *   creating an NtruEncrypt key
 *   <ul>
 *     encrypting a file with a dynamically-generated AES key and wrapping (encrypting) the AES key
 *     with an NtruEncrypt key.
 *     <ul>
 *       decrypting an encrypted file.
 */
@SuppressWarnings("ResultOfMethodCallIgnored")
public class Main {
  /**
   * Creates a public/private key pair and saves the two components to disk.
   *
   * @param prng the source of randomness to use during key creation.
   * @param oid identifies the NtruEncrypt parameter set to use.
   * @param pubFileName where to store the public key.
   * @param privFileName where to store the private key.
   */
  public static void setupNtruEncryptKey(
      Random prng, OID oid, String pubFileName, String privFileName)
      throws IOException, NtruException {
    NtruEncryptKey k = NtruEncryptKey.genKey(oid, prng);

    FileOutputStream pubFile = new FileOutputStream(pubFileName);
    pubFile.write(k.getPubKey());
    pubFile.close();

    FileOutputStream privFile = new FileOutputStream(privFileName);
    privFile.write(k.getPrivKey());
    privFile.close();
  }

  /**
   * Load a public or private NtruEncrypt key blob from disk and instantiate an NtruEncryptKey
   * object from it.
   */
  public static NtruEncryptKey loadKey(String keyFileName) throws IOException, NtruException {
    // Get the file length
    File keyFile = new File(keyFileName);
    long fileLength = keyFile.length();
    if (fileLength > Integer.MAX_VALUE) throw new IOException("file to be encrypted is too large");

    // Load the bytes from the file, instantiate an NtruEncryptKey object,
    // then clean up and return.
    InputStream in = new FileInputStream(keyFile);
    byte[] buf = new byte[(int) fileLength];
    in.read(buf);
    in.close();
    NtruEncryptKey k = new NtruEncryptKey(buf);
    java.util.Arrays.fill(buf, (byte) 0);
    return k;
  }

  /**
   * Encrypt a file, protecting it using the supplied NtruEncrypt key.
   *
   * <p>This method actually performs two levels of encryption. First, the file contents are
   * encrypted using a dynamically-generated AES-256 key in CCM mode. Then the AES key is encrypted
   * with the supplied NtruEncrypt key. The two encrypted blobs, as well as any other non-sensitive
   * data needed for decryption, are writen to disk as "filename.enc".
   *
   * @param ntruKey the NtruEncrypt key to use to wrap the AES key.
   * @param prng the source of randomness used during the NtruEncrypt operation and to generate the
   *     AES key.
   * @param inFileName the name of the soure file. The encrypted data will be written to
   *     "inFileName.enc".
   */
  public static void encryptFile(
      NtruEncryptKey ntruKey, Random prng, String inFileName, String outFileName)
      throws IOException, NtruException {
    // Get the input size
    File inFile = new File(inFileName);
    long fileLength = inFile.length();

    if (fileLength > Integer.MAX_VALUE) throw new IOException("file to be encrypted is too large");

    // Read the contents of the file
    try {
      InputStream in = new FileInputStream(inFile);
      byte[] buf = new byte[(int) fileLength];
      in.read(buf);
      in.close();

      byte[] ivBytes = null;
      byte[] encryptedBuf = null;
      byte[] wrappedAESKey = null;
      try {
        // Get an AES key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey aesKey = keygen.generateKey();

        // Get an IV
        ivBytes = new byte[16];
        prng.read(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Encrypt the plaintext, then zero it out
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        encryptedBuf = cipher.doFinal(buf);
        java.util.Arrays.fill(buf, (byte) 0);

        // Wrap the AES key with the NtruEncrypt key
        byte[] aesKeyBytes = aesKey.getEncoded();
        wrappedAESKey = ntruKey.encrypt(aesKeyBytes, prng);
        java.util.Arrays.fill(aesKeyBytes, (byte) 0);

      } catch (java.security.GeneralSecurityException e) {
        System.out.println("AES error: " + e);
      }

      // Write it to the output file
      FileOutputStream fileOS = new FileOutputStream(outFileName);
      DataOutputStream out = new DataOutputStream(fileOS);
      assert ivBytes != null;
      out.writeInt(ivBytes.length);
      out.write(ivBytes);
      assert wrappedAESKey != null;
      out.writeInt(wrappedAESKey.length);
      out.write(wrappedAESKey);
      out.writeInt(encryptedBuf.length);
      out.write(encryptedBuf);
      out.close();
      fileOS.close();

    } catch (Exception e) {
      System.out.println("File not found error: " + inFileName);
      System.exit(1);
    }
  }

  /**
   * Decrypt a file, reversing the <code>encryptFile</code> operation.
   *
   * @param ntruKey the NtruEncrypt key to use to wrap the AES key.
   * prng the source of randomness used during the NtruEncrypt operation and to generate the
   *     AES key.
   * @param inFileName the name of the soure file. The encrypted data will be written to
   *     "filename.enc".
   */
  public static void decryptFile(NtruEncryptKey ntruKey, String inFileName, String outFileName)
      throws IOException, NtruException {
    // Get the input size
    File inFile = new File(inFileName);
    long fileLength = inFile.length();

    // Parse the contents of the encrypted file
    DataInputStream in = new DataInputStream(new FileInputStream(inFile));
    byte[] ivBytes = new byte[in.readInt()];
    in.readFully(ivBytes);
    byte[] wrappedKey = new byte[in.readInt()];
    in.readFully(wrappedKey);
    byte[] encFileContents = new byte[in.readInt()];
    in.readFully(encFileContents);

    byte[] fileContents = null;
    try {
      // Unwrap the AES key
      byte[] aesKeyBytes = ntruKey.decrypt(wrappedKey);
      SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
      java.util.Arrays.fill(aesKeyBytes, (byte) 0);

      // Decrypt the file contents
      IvParameterSpec iv = new IvParameterSpec(ivBytes);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      fileContents = cipher.doFinal(encFileContents);
    } catch (java.security.GeneralSecurityException e) {
      System.out.println("AES error: " + e);
    }

    // Write it
    OutputStream out = new FileOutputStream(outFileName);
    assert fileContents != null;
    out.write(fileContents);
    out.close();
  }

  /**
   * Creates a com.securityinnovation.jNeo.util.Random object seeded with entropy from
   * java.util.Random.
   */
  static Random createSeededRandom() {
    byte[] seed = new byte[32];
    java.util.Random sysRand = new java.util.Random();
    sysRand.nextBytes(seed);
    return new Random(seed);
  }

  /** Print usage information and exit indicating an error. */
  static void usage() {
    System.out.println("jNeo <OPTIONS> ");
    System.out.println("  --setup <oidName>");
    System.out.println(
        "oidName= one of this: \n"
            + "                       ees401ep1,ees449ep1, ees677ep1,ees1087ep2,\n"
            + "                       ees541ep1,ees613ep1, ees887ep1,ees1171ep1,\n"
            + "                       ees659ep1,ees761ep1,ees1087ep1,ees1499ep1");

    System.out.println("  --pubkey <filename>");
    System.out.println("  --privkey <filename>");
    System.out.println("  --encrypt <inFileName> <outFileName>");
    System.out.println("  --decrypt <inFileName> <outFileName>\n");
    System.out.println("EXAMPLE (make keys): $java -jar jNeo.jar --setup");
    System.out.println("EXAMPLE (encrypt)  : $java -jar jNeo.jar --privkey privKey.key --pubkey pubKey.key --encrypt TestFilePlain.xml ");
    System.out.println("EXAMPLE (encrypt)  : $java -jar jNeo.jar --privkey privKey.key --pubkey pubKey.key --encryptPrivate TestFilePlain.xml ");
    System.out.println("EXAMPLE (decrypt)  : $java -jar jNeo.jar --privkey privKey.key --pubkey pubKey.key --decrypt TestFilePlain.xml.pub.enc");
  }

  /**
   * Given a string containing the name of an OID (e.g. "ees401ep1"), return the OID enum with that
   * name. If there is no OID, exit with an informative message.
   */
  static OID parseOIDName(String requestedOid) {
    try {
      return OID.valueOf(requestedOid);
    } catch (IllegalArgumentException e) {
      System.out.println("Invalid OID! Valid values are:");
      for (OID oid : OID.values()) System.out.println("  " + oid);
      System.exit(1);
    }
    return null;
  }

  public static void main(String[] args) throws IOException, NtruException {

    // Default key file names.
    String pubkeyFile = "pubKey.key";
    String privkeyFile = "privKey.key";
    boolean pubkeyFileFound;
    boolean privkeyFileFound;
    privkeyFileFound = Files.exists(Paths.get(privkeyFile));
    pubkeyFileFound = Files.exists(Paths.get(pubkeyFile));


    if(args.length == 0){
      usage();
    }

    for (int i = 0; i < args.length; i++) {

      switch (args[i]) {
        case "--pubkey":
        {
          if (args[i + 1].startsWith("--")) {
            usage();
            System.exit(1);
          }
          // Setup PRNG
          pubkeyFile = args[i + 1];
          if(pubkeyFileFound = Files.exists(Paths.get(pubkeyFile))){
            System.out.printf("PubKey set:%s%n", FileSystems.getDefault().getPath(pubkeyFile).toAbsolutePath());
          }
          break;
        }

        case "--privkey":
        {
          if (args[i + 1].startsWith("--")) {
            usage();
            System.exit(1);
          }
          // Setup PRNG
          privkeyFile = args[i + 1];
          if(privkeyFileFound = Files.exists(Paths.get(privkeyFile))){
            System.out.printf("PrivatKey set:%s%n", FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath());
          }
          break;
        }
        default:
          break;
      }
    }

    for (int i = 0; i < args.length; i++) {

      System.out.println("args[" + i + "]: " + args[i] + "\n");

      try {
        if (!args[i + 1].startsWith("--") & !args[i + 1].equals(args[i + 2])) {
          System.out.println("args[" + i + "]: " + args[i + 1] + "\n");
        } else {
          System.out.println(
              "we do a key setup now, you will find your keys at the top folder where you executed this app%n"
                  + "PrivKey_Filename: "
                  + FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath()
                  + "%n"
                  + "PubKey_Filename : "
                  + FileSystems.getDefault().getPath(pubkeyFile).toAbsolutePath()
                  + "\n");
        }
      } catch (Exception e) {
        System.out.println("Job finished\n");
      }

      switch (args[i]) {
        case "--setup":
          {
            String requestedOid;
            // Setup PRNG
            if (args[i].startsWith("--")) {
              // usage();
              // setup now default Oid
              requestedOid = "EES587EP1"; // ees1499ep1
              // ees401ep1,ees449ep1,ees677ep1,ees1087ep2,ees541ep1,ees613ep1,ees887ep1,ees1171ep1,ees659ep1,ees761ep1,ees1087ep1,ees1499ep1
            } else {
              requestedOid = args[i + 1];
            }

            Random prng = createSeededRandom();
            OID oid = parseOIDName(requestedOid);

            if (privkeyFileFound || pubkeyFileFound)
            {
              System.out.printf("%s and/or %s found, move them first to a secure place! bye!\n",
                      FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath(),
                      FileSystems.getDefault().getPath(pubkeyFile).toAbsolutePath());

              if (privkeyFileFound){
                Path temp = Files.move
                      (FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath(), Paths.get(String.valueOf(FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath())+ ".bkp"));
                if(temp != null)
                {
                  System.out.println("privkeyFile renamed and moved successfully");
                }
                else
                {
                  System.out.println("privkeyFile Failed to move the file");
                }

              }
              if (pubkeyFileFound){
                Path temp = Files.move
                        (FileSystems.getDefault().getPath(pubkeyFile).toAbsolutePath(), Paths.get(String.valueOf(FileSystems.getDefault().getPath(pubkeyFile).toAbsolutePath())+ ".bkp"));
                if(temp != null)
                {
                  System.out.println("pubkeyFile renamed and moved successfully");
                }
                else
                {
                  System.out.println("pubkeyFile to move the file");
                }

              }

              System.exit(1);
              break;
            }
            setupNtruEncryptKey(prng, oid, pubkeyFile, privkeyFile);
            System.out.printf("PrivatKey generated:%s%n", FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath());
            System.out.printf("PublicKey generated:%s%n", FileSystems.getDefault().getPath(pubkeyFile).toAbsolutePath());
            break;
          }

        case "--encrypt":
        {
          if (privkeyFileFound)
          {
            if (args[i + 1].startsWith("--")) {
              usage();
              System.exit(1);
            }

            String inFileName;
            String outFileName;
            int counter = i + 2;
            int argcount = args.length;
            if (argcount > counter - 1) {
              usage();
              outFileName = args[i + 1] + ".pub.enc";
            }
            else {
              outFileName = args[i + 2];
            }

            inFileName = args[i + 1];
            System.out.printf("we encrypt with pubKey now: %s  to FILE: %s\n%n", inFileName, outFileName);

            // Setup PRNG
            Random prng = createSeededRandom();
            NtruEncryptKey pubKey = loadKey(pubkeyFile);
            encryptFile(pubKey, prng, inFileName, outFileName);

            break;
          }
        }

        case "--encryptPrivate":
        {
          if (privkeyFileFound)
          {
            if (args[i + 1].startsWith("--")) {
              usage();
              System.exit(1);
            }

            String inFileName;
            String outFileName;
            int counter = i + 2;
            int argcount = args.length;
            if (argcount > counter - 1) {
              usage();
              outFileName = args[i + 1] + ".prv.enc";
            }
            else {
              outFileName = args[i + 2];
            }

            inFileName = args[i + 1];
            System.out.printf("we encrypt with privKey now: %s  to FILE: %s\n%n", inFileName, outFileName);

            // Setup PRNG
            Random prng = createSeededRandom();
            NtruEncryptKey privKey = loadKey(privkeyFile);
            encryptFile(privKey, prng, inFileName, outFileName);

            break;
          }
        }

        case "--decrypt":
          if (privkeyFileFound)
          {
            {
            if (args[i + 1].startsWith("--")) {
              usage();
            }

            String inFileName;
            String outFileName;
            int counter = i + 2;
            int argcount = args.length;
            if (argcount > counter - 1) {
              usage();
              outFileName = args[i + 1] + ".priv.dec";
            }
            else {
              outFileName = args[i + 2];
            }

            inFileName = args[i + 1];
            System.out.printf("we decrypt now: %nSOURCE  :%s%nTARGET  :%s %nwith KEY:%s %n",
                    FileSystems.getDefault().getPath(inFileName).toAbsolutePath(),
                    FileSystems.getDefault().getPath(outFileName).toAbsolutePath(),
                    FileSystems.getDefault().getPath(privkeyFile).toAbsolutePath());

            NtruEncryptKey privKey = loadKey(privkeyFile);
            decryptFile(privKey, args[i + 1], outFileName);
            break;
            }
          }

        case "--help":
          {
            usage();
            break;
          }
        default:
          {
            if(i <=1){
              usage();
            }
            break;
          }
      }
    }
  }
}

