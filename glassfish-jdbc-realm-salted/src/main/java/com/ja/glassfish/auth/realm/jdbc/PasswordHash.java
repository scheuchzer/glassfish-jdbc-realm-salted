package com.ja.glassfish.auth.realm.jdbc;

import java.security.SecureRandom;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

/*
 * Based on the java example at https://crackstation.net/hashing-security.htm#javasourcecode
 * by: havoc AT defuse.ca
 */
/**
 * PBKDF2 salted password hashing.
 * 
 * @author havoc AT defuse.ca,
 *         https://crackstation.net/hashing-security.htm#javasourcecode
 * @author Thomas Scheuchzer, Java Adventures.com
 * 
 */
public class PasswordHash {

	public static final String PARAM_HASH_BYTE_SIZE = "hash-byte-size";
	public static final String PARAM_SALT_BYTE_SIZE = "salt-byte-size";
	public static final String PARAM_PBKDF2_ALGORITHM = "pbkdf2-algorithm";
	public static final String PARAM_PBKDF2_ITERATIONS = "pbkdf2-iterations";
	public static final String PARAM_SECURE_RANDOM_ALGORITHM = "secure-random-algorithm";

	public static final int ITERATION_INDEX = 0;
	public static final int SALT_INDEX = 1;
	public static final int PBKDF2_INDEX = 2;

	private String pbkdf2Algorithm = "PBKDF2WithHmacSHA1";
	private String secureRandomAlgorithm = "SHA1PRNG";
	private int saltByteSize = 24;
	private int hashByteSize = 24;
	private int pbkdf2Iterations = 20000;

	/**
	 * Returns a salted PBKDF2 hash of the password.
	 * 
	 * @param password
	 *            the password to hash
	 * @return a salted PBKDF2 hash of the password
	 */
	public String createHash(String password) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		return createHash(password.toCharArray());
	}

	/**
	 * Returns a salted PBKDF2 hash of the password.
	 * 
	 * @param password
	 *            the password to hash
	 * @return a salted PBKDF2 hash of the password
	 */
	public String createHash(char[] password) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Generate a random salt
		SecureRandom random = SecureRandom.getInstance(secureRandomAlgorithm);
		byte[] salt = new byte[saltByteSize];
		random.nextBytes(salt);

		// Hash the password
		byte[] hash = pbkdf2(password, salt, pbkdf2Iterations, hashByteSize);
		// format iterations:salt:hash
		return pbkdf2Iterations + ":" + toHex(salt) + ":" + toHex(hash);
	}

	/**
	 * Validates a password using a hash.
	 * 
	 * @param password
	 *            the password to check
	 * @param correctHash
	 *            the hash of the valid password
	 * @return true if the password is correct, false if not
	 */
	public boolean validatePassword(String password, String correctHash)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return validatePassword(password.toCharArray(), correctHash);
	}

	/**
	 * Validates a password using a hash.
	 * 
	 * @param password
	 *            the password to check
	 * @param correctHash
	 *            the hash of the valid password
	 * @return true if the password is correct, false if not
	 */
	public boolean validatePassword(char[] password, String correctHash)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Decode the hash into its parameters
		String[] params = correctHash.split(":");
		int iterations = Integer.parseInt(params[ITERATION_INDEX]);
		byte[] salt = fromHex(params[SALT_INDEX]);
		byte[] hash = fromHex(params[PBKDF2_INDEX]);
		// Compute the hash of the provided password, using the same salt,
		// iteration count, and hash length
		byte[] testHash = pbkdf2(password, salt, iterations, hash.length);
		// Compare the hashes in constant time. The password is correct if
		// both hashes match.
		return slowEquals(hash, testHash);
	}

	/**
	 * Compares two byte arrays in length-constant time. This comparison method
	 * is used so that password hashes cannot be extracted from an on-line
	 * system using a timing attack and then attacked off-line.
	 * 
	 * @param a
	 *            the first byte array
	 * @param b
	 *            the second byte array
	 * @return true if both byte arrays are the same, false if not
	 */
	private boolean slowEquals(byte[] a, byte[] b) {
		int diff = a.length ^ b.length;
		for (int i = 0; i < a.length && i < b.length; i++)
			diff |= a[i] ^ b[i];
		return diff == 0;
	}

	/**
	 * Computes the PBKDF2 hash of a password.
	 * 
	 * @param password
	 *            the password to hash.
	 * @param salt
	 *            the salt
	 * @param iterations
	 *            the iteration count (slowness factor)
	 * @param bytes
	 *            the length of the hash to compute in bytes
	 * @return the PBDKF2 hash of the password
	 */
	private byte[] pbkdf2(char[] password, byte[] salt, int iterations,
			int bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance(pbkdf2Algorithm);
		return skf.generateSecret(spec).getEncoded();
	}

	/**
	 * Converts a string of hexadecimal characters into a byte array.
	 * 
	 * @param hex
	 *            the hex string
	 * @return the hex string decoded into a byte array
	 */
	private byte[] fromHex(String hex) {
		byte[] binary = new byte[hex.length() / 2];
		for (int i = 0; i < binary.length; i++) {
			binary[i] = (byte) Integer.parseInt(
					hex.substring(2 * i, 2 * i + 2), 16);
		}
		return binary;
	}

	/**
	 * Converts a byte array into a hexadecimal string.
	 * 
	 * @param array
	 *            the byte array to convert
	 * @return a length*2 character string encoding the byte array
	 */
	private String toHex(byte[] array) {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0)
			return String.format("%0" + paddingLength + "d", 0) + hex;
		else
			return hex;
	}

	public void setPbkdf2Algorithm(String pbkdf2Algorithm) {
		this.pbkdf2Algorithm = pbkdf2Algorithm;
	}

	/**
	 * Can be changed without breaking existing hashes.
	 */
	public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
		this.secureRandomAlgorithm = secureRandomAlgorithm;
	}

	/**
	 * Can be changed without breaking existing hashes.
	 */
	public void setSaltByteSize(int saltByteSize) {
		this.saltByteSize = saltByteSize;
	}

	/**
	 * Can be changed without breaking existing hashes.
	 */
	public void setHashByteSize(int hashByteSize) {
		this.hashByteSize = hashByteSize;
	}

	/**
	 * 
	 * Pick an iteration count that works for you. Can be changed without
	 * breaking existing hashes.
	 * <p>
	 * The NIST recommends at least <a href=
	 * "http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf"
	 * >1,000 iterations</a> <br/>
	 * iOS 4.x reportedly uses <a href=
	 * "http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords"
	 * >10000</a>
	 * </p>
	 */
	public void setPbkdf2Iterations(int pbkdf2Iterations) {
		this.pbkdf2Iterations = pbkdf2Iterations;
	}

	public void configure(Properties props) {
		if (props.getProperty(PARAM_HASH_BYTE_SIZE) != null) {
			setHashByteSize(Integer.parseInt(props
					.getProperty(PARAM_HASH_BYTE_SIZE)));
		}
		if (props.getProperty(PARAM_SALT_BYTE_SIZE) != null) {
			setHashByteSize(Integer.parseInt(props
					.getProperty(PARAM_SALT_BYTE_SIZE)));
		}
		if (props.getProperty(PARAM_PBKDF2_ALGORITHM) != null) {
			setPbkdf2Algorithm(props.getProperty(PARAM_PBKDF2_ALGORITHM));
		}
		if (props.getProperty(PARAM_PBKDF2_ITERATIONS) != null) {
			setPbkdf2Iterations(Integer.parseInt(props
					.getProperty(PARAM_PBKDF2_ITERATIONS)));
		}
		if (props.getProperty(PARAM_SECURE_RANDOM_ALGORITHM) != null) {
			setSecureRandomAlgorithm(props
					.getProperty(PARAM_SECURE_RANDOM_ALGORITHM));
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + hashByteSize;
		result = prime * result
				+ ((pbkdf2Algorithm == null) ? 0 : pbkdf2Algorithm.hashCode());
		result = prime * result + pbkdf2Iterations;
		result = prime * result + saltByteSize;
		result = prime
				* result
				+ ((secureRandomAlgorithm == null) ? 0 : secureRandomAlgorithm
						.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PasswordHash other = (PasswordHash) obj;
		if (hashByteSize != other.hashByteSize)
			return false;
		if (pbkdf2Algorithm == null) {
			if (other.pbkdf2Algorithm != null)
				return false;
		} else if (!pbkdf2Algorithm.equals(other.pbkdf2Algorithm))
			return false;
		if (pbkdf2Iterations != other.pbkdf2Iterations)
			return false;
		if (saltByteSize != other.saltByteSize)
			return false;
		if (secureRandomAlgorithm == null) {
			if (other.secureRandomAlgorithm != null)
				return false;
		} else if (!secureRandomAlgorithm.equals(other.secureRandomAlgorithm))
			return false;
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PasswordHash [pbkdf2Algorithm=")
				.append(pbkdf2Algorithm).append(", secureRandomAlgorithm=")
				.append(secureRandomAlgorithm).append(", saltByteSize=")
				.append(saltByteSize).append(", hashByteSize=")
				.append(hashByteSize).append(", pbkdf2Iterations=")
				.append(pbkdf2Iterations).append("]");
		return builder.toString();
	}

}
