package server;

import common.User;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.Base64;
import java.util.Properties;

public class AccountService {

    private static final Path FILE = Path.of("users.properties");
    private static final SecureRandom RANDOM = new SecureRandom();

    private static Properties load() throws IOException {
        Properties accounts = new Properties();

        if (Files.exists(FILE)) {
            try (InputStream input = Files.newInputStream(FILE)) {
                accounts.load(input);
            }
        }

        return accounts;
    }

    private static void save(Properties accounts) throws IOException {
        Path temporary = Path.of("users.properties.tmp");

        try (OutputStream output = Files.newOutputStream(temporary)) {
            accounts.store(output, "JavaChat accounts");
        }

        try {
            Files.move(
                    temporary, FILE,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
            );
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(
                    temporary, FILE,
                    StandardCopyOption.REPLACE_EXISTING
            );
        }
    }

    private static byte[] hash(String password, byte[] salt)
            throws GeneralSecurityException {

        PBEKeySpec specification = new PBEKeySpec(
                password.toCharArray(), salt, 600_000, 256
        );

        try {
            return SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification)
                    .getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    public static synchronized User register(
            String username, String password
    ) throws IOException, GeneralSecurityException {

        if (!username.matches("[A-Za-z0-9_]{1,20}")) {
            throw new IllegalArgumentException(
                    "Username: use 1-20 letters, numbers, or underscores."
            );
        }

        if (password.length() < 8) {
            throw new IllegalArgumentException(
                    "Password must contain at least 8 characters."
            );
        }

        Properties accounts = load();

        if (accounts.containsKey(username)) {
            throw new IllegalArgumentException(
                    "Username already exists."
            );
        }

        byte[] saltBytes = new byte[16];
        RANDOM.nextBytes(saltBytes);

        String salt = Base64.getEncoder()
                .encodeToString(saltBytes);

        String passwordHash = Base64.getEncoder()
                .encodeToString(hash(password, saltBytes));

        User user = new User(
                User.generateId(), username, salt, passwordHash
        );

        accounts.setProperty(
                username,
                user.getId() + "|" + salt + "|" + passwordHash
        );

        save(accounts);
        return user;
    }

    public static synchronized User login(
            String username, String password
    ) throws IOException, GeneralSecurityException {

        Properties accounts = load();
        String record = accounts.getProperty(username);

        if (record == null) {
            return null;
        }

        String[] fields = record.split("\\|", -1);

        if (fields.length != 3) {
            throw new IOException("Invalid account record.");
        }

        try {
            byte[] salt = Base64.getDecoder().decode(fields[1]);
            byte[] expected = Base64.getDecoder().decode(fields[2]);
            byte[] actual = hash(password, salt);

            if (!MessageDigest.isEqual(expected, actual)) {
                return null;
            }

            return new User(
                    fields[0], username, fields[1], fields[2]
            );

        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid account data.", e);
        }
    }
}