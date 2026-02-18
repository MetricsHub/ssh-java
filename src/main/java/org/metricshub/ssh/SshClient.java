/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.metricshub.ssh;

/*-
 * ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲
 * SSH Java Client
 * ჻჻჻჻჻჻
 * Copyright (C) 2023 Metricshub
 * ჻჻჻჻჻჻
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱
 */

import com.trilead.ssh2.ChannelCondition;
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.InteractiveCallback;
import com.trilead.ssh2.SCPClient;
import com.trilead.ssh2.SFTPv3Client;
import com.trilead.ssh2.SFTPv3DirectoryEntry;
import com.trilead.ssh2.SFTPv3FileAttributes;
import com.trilead.ssh2.SFTPv3FileHandle;
import com.trilead.ssh2.Session;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Optional;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SSH Client that lets you perform basic SSH operations
 * <ol>
 * <li>Instantiate the SSH Client
 * <li>Connect
 * <li>Authenticate
 * <li>Enjoy!
 * <li><b>DISCONNECT!</b>
 * </ol>
 *
 * @author Bertrand
 */
public class SshClient implements AutoCloseable {

	private static final Pattern DEFAULT_MASK_PATTERN = Pattern.compile(".*");

	private static final int READ_BUFFER_SIZE = 8192;

	private String hostname;
	private Connection sshConnection = null;

	private Charset charset = null;

	/**
	 * Session object that needs to be closed when we disconnect
	 */
	private Session sshSession = null;

	/**
	 * Creates an SSHClient to connect to the specified hostname
	 *
	 * @param pHostname Hostname of the SSH server to connect to
	 */
	public SshClient(String pHostname) {
		this(pHostname, "");
	}

	/**
	 * Creates an SSHClient to connect to the specified hostname
	 *
	 * @param pHostname Hostname of the SSH server to connect to
	 * @param pLocale Locale used on the remote server (e.g. zh_CN.utf8)
	 */
	public SshClient(String pHostname, String pLocale) {
		this(pHostname, Utils.getCharsetFromLocale(pLocale));
	}

	/**
	 * Creates an SSHClient to connect to the specified hostname
	 *
	 * @param pHostname Hostname of the SSH server to connect to
	 * @param pCharset Charset used on the remote server
	 */
	public SshClient(String pHostname, Charset pCharset) {
		hostname = pHostname;
		charset = pCharset;
	}

	/**
	 * Connects the SSH Client to the SSH server
	 *
	 * @throws IOException
	 */
	public void connect() throws IOException {
		connect(0);
	}

	/**
	 * Connects the SSH client to the SSH server using the default SSH port (22).
	 *
	 * @param timeout Timeout in milliseconds
	 * @throws IOException when connection fails or when the server does not respond (SocketTimeoutException)
	 */
	public void connect(final int timeout) throws IOException {
		this.connect(timeout, 22);
	}

	/**
	 *  Connects the SSH client to the SSH server using a specified SSH port.
	 *
	 * @param timeout Timeout in milliseconds
	 * @param port SSH server port.
	 * @throws IOException when connection fails or when the server does not respond (SocketTimeoutException)
	 */
	public void connect(final int timeout, final int port) throws IOException {
		sshConnection = new Connection(hostname, port);
		sshConnection.connect(null, timeout, timeout);
	}

	/**
	 * Disconnects the SSH Client from the SSH server
	 * <p>
	 * Note: <b>This is important!</b> Otherwise, the listener thread will
	 * remain running forever!
	 * Use a try with resource instead or the {@link close} instead.
	 * @deprecated (since = "3.14.00", forRemoval = true)
	 */
	@Deprecated
	public void disconnect() {
		if (sshSession != null) {
			sshSession.close();
		}
		if (sshConnection != null) {
			sshConnection.close();
		}
	}

	/**
	 * Disconnects the SSH Client from the SSH server
	 * <p>
	 * Note: <b>This is important!</b> Otherwise, the listener thread will
	 * remain running forever!
	 */
	@Override
	public void close() {
		if (sshSession != null) {
			sshSession.close();
		}
		if (sshConnection != null) {
			sshConnection.close();
		}
	}

	/**
	 * Authenticate the SSH Client against the SSH server using a private key
	 *
	 * @deprecated (since = "3.14.00", forRemoval = true)
	 * @param username
	 * @param privateKeyFile
	 * @param password
	 * @return a boolean stating whether the authentication worked or not
	 * @throws IOException
	 */
	@Deprecated
	public boolean authenticate(String username, String privateKeyFile, String password) throws IOException {
		return authenticate(
			username,
			privateKeyFile != null ? new File(privateKeyFile) : null,
			password != null ? password.toCharArray() : null
		);
	}

	/**
	 * Authenticate the SSH Client against the SSH server using a private key
	 *
	 * @param username
	 * @param privateKeyFile
	 * @param password
	 * @return a boolean stating whether the authentication worked or not
	 * @throws IOException
	 */
	public boolean authenticate(String username, File privateKeyFile, char[] password) throws IOException {
		if (sshConnection.isAuthMethodAvailable(username, "publickey")) {
			return sshConnection.authenticateWithPublicKey(
				username,
				privateKeyFile,
				password != null ? String.valueOf(password) : null
			);
		}

		return false;
	}

	/**
	 * Authenticate the SSH Client against the SSH server using a password
	 *
	 * @deprecated (since = "3.14.00", forRemoval = true)
	 * @param username
	 * @param password
	 * @return a boolean stating whether the authentication worked or not
	 * @throws IOException
	 */
	@Deprecated
	public boolean authenticate(String username, String password) throws IOException {
		return authenticate(username, password != null ? password.toCharArray() : null);
	}

	/**
	 * Authenticate the SSH Client against the SSH server using a password
	 *
	 * @param username
	 * @param password
	 * @return a boolean stating whether the authentication worked or not
	 * @throws IOException
	 */
	public boolean authenticate(String username, char[] password) throws IOException {
		// Is the "password" method available? If yes, try it first
		// Using normal login & password
		if (
			sshConnection.isAuthMethodAvailable(username, "password") &&
			sshConnection.authenticateWithPassword(username, password != null ? String.valueOf(password) : null)
		) {
			return true;
		}

		// Now, is the "keyboard-interactive" method available?
		if (sshConnection.isAuthMethodAvailable(username, "keyboard-interactive")) {
			return sshConnection.authenticateWithKeyboardInteractive(
				username,
				new InteractiveCallback() {
					@Override
					public String[] replyToChallenge(
						String name,
						String instruction,
						int numPrompts,
						String[] prompt,
						boolean[] echo
					) throws Exception {
						// Prepare responses to the challenges
						String[] challengeResponse = new String[numPrompts];
						for (int i = 0; i < numPrompts; i++) {
							// If we're told the input can be displayed (echoed),
							// we'll assume this is not a password
							// that we're being asked for, hence the username.
							// Otherwise, we'll send the password
							if (echo[i]) {
								challengeResponse[i] = username;
							} else {
								challengeResponse[i] = password != null ? String.valueOf(password) : null;
							}
						}
						return challengeResponse;
					}
				}
			);
		}

		// If none of the above methods are available, just quit
		return false;
	}

	/**
	 * Authenticate the SSH Client against the SSH server using NO password
	 *
	 * @param username
	 * @return a boolean stating whether the authentication worked or not
	 * @throws IOException
	 */
	public boolean authenticate(String username) throws IOException {
		return sshConnection.authenticateWithNone(username);
	}

	/**
	 * Return information about the specified file on the connected system, in
	 * the same format as the PSL function <code>file()</code>
	 *
	 * @param filePath
	 *            Path to the file on the remote system
	 * @throws IOException
	 */
	public String readFileAttributes(String filePath) throws IOException {
		// Sanity check
		checkIfAuthenticated();

		// Create the SFTP client
		SFTPv3Client sftpClient = new SFTPv3Client(sshConnection);

		// Read the file attributes
		SFTPv3FileAttributes fileAttributes = sftpClient.stat(filePath);

		// Determine the file type
		String fileType;
		if (fileAttributes.isRegularFile()) {
			fileType = "FILE";
		} else if (fileAttributes.isDirectory()) {
			fileType = "DIR";
		} else if (fileAttributes.isSymlink()) {
			fileType = "LINK";
		} else {
			fileType = "UNKNOWN";
		}

		// Build the result in the same format as the PSL function file()
		StringBuilder pslFileResult = new StringBuilder();
		pslFileResult
			.append(fileAttributes.mtime.toString())
			.append("\t")
			.append(fileAttributes.atime.toString())
			.append("\t-\t")
			.append(Integer.toString(fileAttributes.permissions & 0000777, 8))
			.append("\t")
			.append(fileAttributes.size.toString())
			.append("\t-\t")
			.append(fileType)
			.append("\t")
			.append(fileAttributes.uid.toString())
			.append("\t")
			.append(fileAttributes.gid.toString())
			.append("\t")
			.append(sftpClient.canonicalPath(filePath));

		// Deallocate
		sftpClient.close();

		// Return
		return pslFileResult.toString();
	}

	/**
	 * Returns the file size.
	 *
	 * @param filePath Path to the file on the remote system
	 * @return the file size
	 * @throws IOException if the file does not exist
	 */
	public long fileSize(final String filePath) throws IOException {
		// Sanity check
		checkIfAuthenticated();

		// Create the SFTP client
		SFTPv3Client sftpClient = new SFTPv3Client(sshConnection);

		// Read the file attributes
		final SFTPv3FileAttributes attributes = sftpClient.stat(filePath);

		// Deallocate
		sftpClient.close();

		return attributes.size;
	}

	private StringBuilder listSubDirectory(
		SFTPv3Client sftpClient,
		String remoteDirectoryPath,
		Pattern fileMaskPattern,
		boolean includeSubfolders,
		Integer depth,
		StringBuilder resultBuilder
	) throws IOException {
		if (depth <= 15) {
			@SuppressWarnings("unchecked")
			Vector<SFTPv3DirectoryEntry> pathContents = sftpClient.ls(remoteDirectoryPath);

			// Fix the remoteDirectoryPath (without the last '/')
			if (remoteDirectoryPath.endsWith("/")) {
				remoteDirectoryPath = remoteDirectoryPath.substring(0, remoteDirectoryPath.lastIndexOf("/"));
			}

			depth++;
			for (SFTPv3DirectoryEntry file : pathContents) {
				String filename = file.filename.trim();

				if (filename.equals(".") || filename.equals("..")) {
					continue;
				}

				SFTPv3FileAttributes fileAttributes = file.attributes;
				String filePath = remoteDirectoryPath + "/" + filename;

				if ((fileAttributes.permissions & 0120000) == 0120000) {
					// Symbolic link
					continue;
				}

				// CHECKSTYLE:OFF
				if (
					((fileAttributes.permissions & 0100000) == 0100000) ||
					((fileAttributes.permissions & 0060000) == 0060000) ||
					((fileAttributes.permissions & 0020000) == 0020000) ||
					((fileAttributes.permissions & 0140000) == 0140000)
				) {
					// Regular/Block/Character/Socket files
					final Matcher m = fileMaskPattern.matcher(filename);
					if (m.find()) {
						resultBuilder
							.append(filePath)
							.append(";")
							.append(fileAttributes.mtime.toString())
							.append(";")
							.append(fileAttributes.size.toString())
							.append("\n");
					}
					continue;
				}
				// CHECKSTYLE:ON

				if ((fileAttributes.permissions & 0040000) == 0040000) {
					// Directory
					if (includeSubfolders) {
						resultBuilder =
							listSubDirectory(sftpClient, filePath, fileMaskPattern, includeSubfolders, depth, resultBuilder);
					}
				}
			}
		}

		return resultBuilder;
	}

	/**
	 * List the content of the specified directory through the SSH connection
	 * (using SCP)
	 *
	 * @param remoteDirectoryPath The path to the directory to list on the remote host
	 * @param regExpFileMask A regular expression that listed files must match with to be listed
	 * @param includeSubfolders Whether to parse subdirectories as well
	 * @return The list of files in the specified directory, separated by end-of-lines
	 *
	 * @throws IOException When something bad happens while communicating with the remote host
	 * @throws IllegalStateException If called while not yet connected
	 */
	public String listFiles(String remoteDirectoryPath, String regExpFileMask, boolean includeSubfolders)
		throws IOException {
		checkIfAuthenticated();

		// Create an SFTP Client
		SFTPv3Client sftpClient = new SFTPv3Client(sshConnection);

		// Prepare the Pattern for fileMask
		Pattern fileMaskPattern;
		if (regExpFileMask != null && !regExpFileMask.isEmpty()) {
			fileMaskPattern = Pattern.compile(regExpFileMask, Pattern.CASE_INSENSITIVE);
		} else {
			fileMaskPattern = DEFAULT_MASK_PATTERN;
		}

		// Read the directory listing
		StringBuilder resultBuilder = new StringBuilder();
		listSubDirectory(sftpClient, remoteDirectoryPath, fileMaskPattern, includeSubfolders, 1, resultBuilder);

		// Close the SFTP client
		sftpClient.close();

		// Update the response
		return resultBuilder.toString();
	}

	/**
	 * Read the specified file over the SSH session that was established.
	 *
	 * @param remoteFilePath
	 *            Path to the file to be read on the remote host
	 * @param readOffset
	 *            Offset to read from
	 * @param readSize
	 *            Amount of bytes to be read
	 * @return The content of the file read
	 *
	 * @throws IOException
	 *             when something gets wrong while reading the file (we get
	 *             disconnected, for example, or we couldn't read the file)
	 * @throws IllegalStateException
	 *             when the session hasn't been properly authenticated first
	 */
	public String readFile(String remoteFilePath, Long readOffset, Integer readSize) throws IOException {
		checkIfAuthenticated();

		// Create an SFTP Client
		SFTPv3Client sftpClient = new SFTPv3Client(sshConnection);

		// Where do we read from (offset)?
		long offset = 0; // from the beginning by default
		if (readOffset != null) {
			offset = readOffset; // use the set offset
		}

		// Open the remote file
		SFTPv3FileHandle handle = sftpClient.openFileRO(remoteFilePath);

		// How much data to read?
		int remainingBytes;
		if (readSize == null) {
			// If size was not specified, we read the file entirely
			SFTPv3FileAttributes attributes = sftpClient.fstat(handle);
			if (attributes == null) {
				throw new IOException("Couldn't find file " + remoteFilePath + " and get its attributes");
			}
			remainingBytes = (int) (attributes.size - offset);
			if (remainingBytes < 0) {
				remainingBytes = 0;
			}
		} else {
			remainingBytes = readSize;
		}

		// Read the remote file
		OutputStream out = new ByteArrayOutputStream();
		byte[] readBuffer = new byte[READ_BUFFER_SIZE];
		int bytesRead;
		int bufferSize;

		// Loop until there is nothing else to read
		while (remainingBytes > 0) {
			// Read by chunk of 8192 bytes. However, if there is less to read,
			// well, read less.
			if (remainingBytes < READ_BUFFER_SIZE) {
				bufferSize = remainingBytes;
			} else {
				bufferSize = READ_BUFFER_SIZE;
			}

			// Read and store that in our buffer
			bytesRead = sftpClient.read(handle, offset, readBuffer, 0, bufferSize);

			// If we already reached the end of the file, exit (probably, we
			// were asked to read more than what is available)
			if (bytesRead < 0) {
				break;
			}

			// Write our buffer to the result stream
			out.write(readBuffer, 0, bytesRead);

			// Keep counting!
			remainingBytes -= bytesRead;
			offset += bytesRead;
		}

		// File read complete
		// Close the remote file
		sftpClient.closeFile(handle);

		// Close the SFTP client
		sftpClient.close();

		// Metricshub Collection format
		return out.toString();
	}

	/**
	 * Removes a list of files on the remote system.
	 *
	 * @param remoteFilePathArray Array of paths to the files to be deleted on the remote host
	 * @throws IOException when something bad happens while deleting the file
	 * @throws IllegalStateException when not connected and authenticated yet
	 */
	public void removeFile(String[] remoteFilePathArray) throws IOException {
		checkIfAuthenticated();

		// Create an SFTP Client
		SFTPv3Client sftpClient = null;
		try {
			sftpClient = new SFTPv3Client(sshConnection);

			// Remove the files
			for (String remoteFilePath : remoteFilePathArray) {
				sftpClient.rm(remoteFilePath);
			}
		} catch (IOException e) {
			// Okay, we got an issue here with the SFTP client
			// We're going to try again but with a good old "rm" command...

			Session rmSession = null;
			try {
				for (String remoteFilePath : remoteFilePathArray) {
					rmSession = sshConnection.openSession();
					rmSession.execCommand("/usr/bin/rm -f \"" + remoteFilePath + "\"");
					rmSession.waitForCondition(ChannelCondition.CLOSED | ChannelCondition.EOF, 5000);
				}
			} catch (IOException e1) {
				throw e1;
			} finally {
				if (rmSession != null) {
					rmSession.close();
				}
			}
		} finally {
			// Close the SFTP client
			if (sftpClient != null) {
				sftpClient.close();
			}
		}
	}

	/**
	 * Removes the specified file on the remote system.
	 *
	 * @param remoteFilePath
	 * @throws IOException
	 * @throws IllegalStateException
	 */
	public void removeFile(String remoteFilePath) throws IOException {
		removeFile(new String[] { remoteFilePath });
	}

	/**
	 * Represents the result of a command execution
	 *
	 * @author bertrand
	 *
	 */
	public static class CommandResult {

		/**
		 * Whether the command was successful or not
		 */
		public boolean success = true;

		/**
		 * How much time was taken by the execution itself (not counting the
		 * connection time), in seconds
		 */
		public float executionTime = 0;

		/**
		 * The exit code (status) returned by the command (process return code).
		 * <code>null</code> if unsupported by the remote platform.
		 */
		public Integer exitStatus = null;

		/**
		 * The result of the command (stdout and stderr is merged into result)
		 */
		public String result = "";
	}

	/**
	 * Executes a command through the SSH connection
	 *
	 * @param command	The command to be executed
	 * @return a CommandResult object with the result of the execution
	 * @throws IllegalStateException when the connection is not established first
	 * @throws IOException when there is a problem while communicating with the remote system
	 */
	public CommandResult executeCommand(String command) throws IOException {
		return executeCommand(command, 0);
	}

	/**
	 * Executes a command through the SSH connection
	 *
	 * @param command	The command to be executed
	 * @param timeout	Milliseconds after which the command is considered failed
	 * @return a CommandResult object with the result of the execution
	 * @throws IllegalStateException when the connection is not established first
	 * @throws IOException when there is a problem while communicating with the remote system
	 */
	public CommandResult executeCommand(String command, int timeout) throws IOException {
		openSession();

		InputStream stdout = sshSession.getStdout();
		InputStream stderr = sshSession.getStderr();
		// DO NOT request for a PTY, as Trilead SSH's execCommand() would get stuck on AIX...
		//sshSession.requestPTY("dumb", 10000, 24, 640, 480, new byte[] {53, 0, 0, 0, 0, 0}); // request for a wiiiiide terminal

		// Initialization
		CommandResult commandResult = new CommandResult();

		// Output to a byte stream
		try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			// Time to be remembered
			long startTime = System.currentTimeMillis();
			long timeoutTime;
			if (timeout > 0) {
				timeoutTime = startTime + timeout;
			} else {
				// If no timeout, we use the max long value for the time when we're supposed to stop
				timeoutTime = Long.MAX_VALUE;
			}

			// Run the command
			sshSession.execCommand(command);

			int waitForCondition = 0;
			long currentTime;
			// CHECKSTYLE:OFF
			while (
				!hasSessionClosed(waitForCondition) &&
				!hasEndOfFileSession(waitForCondition) &&
				((currentTime = System.currentTimeMillis()) < timeoutTime)
			) {
				// Wait for new data (timeout = 5 seconds)
				waitForCondition = waitForNewData(Math.min(timeoutTime - currentTime, 5000));

				// Print available data (if any)
				if (hasStdoutData(waitForCondition)) {
					transferAllBytes(stdout, output);
				}

				if (hasStderrData(waitForCondition)) {
					transferAllBytes(stderr, output);
				}
			}
			// CHECKSTYLE:ON

			// What time is it?
			currentTime = System.currentTimeMillis();
			if (currentTime >= timeoutTime) {
				// If we exceeded the timeout, we're not successful

				// Build the "timed out" result
				commandResult.success = false;
				commandResult.result = "Timeout (" + timeout / 1000 + " seconds)";
			} else {
				// We completed in time

				// Execution time (in seconds)
				commandResult.executionTime = (currentTime - startTime) / 1000;

				// Read exit status, when available
				waitForCondition = sshSession.waitForCondition(ChannelCondition.EXIT_STATUS, 5000);
				if ((waitForCondition & ChannelCondition.EXIT_STATUS) != 0) {
					commandResult.exitStatus = sshSession.getExitStatus();
				}

				// Stringify the stdout stream
				commandResult.result = new String(output.toByteArray(), charset);
			}
		}

		// Return
		return commandResult;
	}

	/**
	 * Starts an interactive session.
	 *
	 * @param in Where the input is coming from (typically System.in)
	 * @param out Where the output has to go (e.g. System.out)
	 * @throws IllegalStateException when not connected and authenticated
	 * @throws IOException in case of communication problems with the host
	 * @throws InterruptedException when a thread is interrupted
	 */
	public void interactiveSession(InputStream in, OutputStream out) throws IOException, InterruptedException {
		openSession();

		openTerminal();

		// Pipe specified InputStream to SSH's stdin -- use a separate thread
		BufferedReader inputReader = new BufferedReader(new InputStreamReader(in));
		OutputStream outputWriter = sshSession.getStdin();
		Thread stdinPipeThread = new Thread() {
			@Override
			public void run() {
				try {
					String line;
					while ((line = inputReader.readLine()) != null) {
						outputWriter.write(line.getBytes());
						outputWriter.write('\n');
					}
				} catch (Exception e) {
					// Things ended up badly. Exit thread.
				}
				// End of the input stream. We need to exit.
				// Let's close the session so the main thread exits nicely.
				sshSession.close();
			}
		};
		stdinPipeThread.setDaemon(true);
		stdinPipeThread.start();

		// Now, pipe stdout and stderr to specified OutputStream
		InputStream stdout = sshSession.getStdout();
		InputStream stderr = sshSession.getStderr();

		int waitForCondition = 0;
		while (!hasSessionClosed(waitForCondition) && !hasEndOfFileSession(waitForCondition)) {
			// Wait for new data (timeout = 5 seconds)
			waitForCondition = waitForNewData(5000L);

			// Print available data (if any)
			if (hasStdoutData(waitForCondition)) {
				transferAllBytes(stdout, out);
			}

			if (hasStderrData(waitForCondition)) {
				transferAllBytes(stderr, out);
			}
		}

		// Attempt to interrupt the stdinPipeThread thread
		// (may be useless if we're reading a blocking InputStream like System.in)
		if (stdinPipeThread.isAlive()) {
			stdinPipeThread.interrupt();
		}
	}

	/**
	 * Copy a file to the remote host through SCP
	 *
	 * @param localFilePath
	 * @param remoteFilename
	 * @param remoteDirectory
	 * @param fileMode
	 * @throws IOException
	 */
	public void scp(String localFilePath, String remoteFilename, String remoteDirectory, String fileMode)
		throws IOException {
		checkIfAuthenticated();

		// Create the SCP client
		SCPClient scpClient = new SCPClient(sshConnection);

		// Copy the file
		scpClient.put(localFilePath, remoteFilename, remoteDirectory, fileMode);
	}

	/**
	 * Open a SSH Session.
	 *
	 * @throws IOException When an I/O error occurred.
	 */
	public void openSession() throws IOException {
		checkIfConnected();
		checkIfAuthenticated();

		// Open a shell session
		sshSession = getSshConnection().openSession();
	}

	/**
	 * Open a Terminal
	 * request for a wiiiiide terminal, with no ECHO (see https://tools.ietf.org/html/rfc4254#section-8)
	 *
	 * @throws IOException When an I/O error occurred.
	 */
	public void openTerminal() throws IOException {
		checkIfConnected();
		checkIfAuthenticated();
		checkIfSessionOpened();

		getSshSession().requestPTY("dumb", 10000, 24, 640, 480, new byte[] { 53, 0, 0, 0, 0, 0 });
		getSshSession().startShell();
	}

	/**
	 * Write into the SSH session.
	 *
	 * @param text The text to be written.
	 * @throws IOException When an I/O error occurred.
	 */
	public void write(final String text) throws IOException {
		if (text == null || text.isEmpty()) {
			return;
		}

		checkIfConnected();
		checkIfAuthenticated();
		checkIfSessionOpened();

		Utils.checkNonNullField(charset, "charset");

		final OutputStream outputStream = getSshSession().getStdin();
		Utils.checkNonNullField(outputStream, "Stdin");

		// Replace "\n" string with write of '\n' character.
		final String[] split = text.split("\\R", -1);
		if (split.length == 1) {
			outputStream.write(text.getBytes(charset));
		} else {
			for (int i = 0; i < split.length; i++) {
				if (split[i].length() != 0) {
					outputStream.write(split[i].getBytes(charset));
				}

				if (i < split.length - 1) {
					outputStream.write('\n');
				}
			}
		}

		outputStream.flush();
	}

	/**
	 * Read the stdout and stderr from the SSH session.
	 *
	 * @param size The buffer size of stdout and/or stderr to be read. (If less than 0 all data)
	 * @param timeout Timeout in seconds
	 *
	 * @return An optional with all the data read (stdout and stderr). Empty if nothing was read.
	 * @throws IOException When an I/O error occurred.
	 */
	public Optional<String> read(final int size, final int timeout) throws IOException {
		Utils.checkArgumentNotZeroOrNegative(timeout, "timeout");

		checkIfConnected();
		checkIfAuthenticated();
		checkIfSessionOpened();

		Utils.checkNonNullField(charset, "charset");

		final InputStream stdout = getSshSession().getStdout();
		final InputStream stderr = getSshSession().getStderr();
		Utils.checkNonNullField(stdout, "stdout");
		Utils.checkNonNullField(stderr, "stderr");

		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
			// Wait for new data
			final int waitForCondition = waitForNewData(timeout * 1000L);

			final boolean stdoutData = hasStdoutData(waitForCondition);
			final boolean stderrData = hasStderrData(waitForCondition);

			// read stdout
			int stdoutRead = 0;
			if (stdoutData) {
				stdoutRead = transferBytes(stdout, byteArrayOutputStream, size);
				if (size > 0 && stdoutRead >= size) {
					return Optional.of(new String(byteArrayOutputStream.toByteArray(), charset));
				}
			}

			// If still bytes to read or no stdout, read stderr
			if (stderrData) {
				transferBytes(stderr, byteArrayOutputStream, size - stdoutRead);
			}

			return stdoutData || stderrData
				? Optional.of(new String(byteArrayOutputStream.toByteArray(), charset))
				: Optional.empty();
		}
	}

	/**
	 * Check if the waitForCondition bit mask contains the timeout condition.
	 *
	 * @param waitForCondition The waitForCondition bit mask
	 * @return true if the bit mask contains the condition, false otherwise
	 */
	static boolean hasTimeoutSession(final int waitForCondition) {
		return (waitForCondition & ChannelCondition.TIMEOUT) != 0;
	}

	/**
	 * Check if the waitForCondition bit mask contains the end of file condition.
	 *
	 * @param waitForCondition The waitForCondition bit mask
	 * @return true if the bit mask contains the condition, false otherwise
	 */
	static boolean hasEndOfFileSession(final int waitForCondition) {
		return (waitForCondition & ChannelCondition.EOF) != 0;
	}

	/**
	 * Check if the waitForCondition bit mask contains the session closed condition.
	 *
	 * @param waitForCondition The waitForCondition bit mask
	 * @return true if the bit mask contains the condition, false otherwise
	 */
	static boolean hasSessionClosed(final int waitForCondition) {
		return (waitForCondition & ChannelCondition.CLOSED) != 0;
	}

	/**
	 * Check if the waitForCondition bit mask contains the stdout data condition.
	 *
	 * @param waitForCondition The waitForCondition bit mask
	 * @return true if the bit mask contains the condition, false otherwise
	 */
	static boolean hasStdoutData(final int waitForCondition) {
		return (waitForCondition & ChannelCondition.STDOUT_DATA) != 0;
	}

	/**
	 * Check if the waitForCondition bit mask contains the stderr data condition.
	 *
	 * @param waitForCondition The waitForCondition bit mask
	 * @return true if the bit mask contains the condition, false otherwise
	 */
	static boolean hasStderrData(final int waitForCondition) {
		return (waitForCondition & ChannelCondition.STDERR_DATA) != 0;
	}

	/**
	 * <p>Wait until the session contains at least one of the condition:
	 * <li>stdout data</li>
	 * <li>stderr data</li>
	 * <li>end of file</li>
	 * <li>session closed</li>
	 * </p>
	 * @param timeout Timeout in milliseconds
	 * @return A bit mask specifying all current conditions that are true
	 */
	int waitForNewData(final long timeout) {
		return sshSession.waitForCondition(
			ChannelCondition.STDOUT_DATA | ChannelCondition.STDERR_DATA | ChannelCondition.EOF | ChannelCondition.CLOSED,
			timeout
		);
	}

	/**
	 * Check if the SSH connection exists.
	 */
	void checkIfConnected() {
		if (getSshConnection() == null) {
			throw new IllegalStateException("Connection is required first");
		}
	}

	/**
	 * Check if already authenticate.
	 */
	void checkIfAuthenticated() {
		if (getSshConnection() == null || !getSshConnection().isAuthenticationComplete()) {
			throw new IllegalStateException("Authentication is required first");
		}
	}

	/**
	 * Check if the SSH session exists.
	 */
	public void checkIfSessionOpened() {
		if (getSshSession() == null) {
			throw new IllegalStateException("SSH session should be opened first");
		}
	}

	/**
	 * Read all the bytes from the inputstream and write them into a string in the outputstream.
	 *
	 * @param inputStream The inputStream.
	 * @param outputStream The outputstream.
	 * @return The total number of copy bytes.
	 * @throws IOException When an I/O error occurred.
	 */
	static int transferAllBytes(final InputStream inputStream, final OutputStream outputStream) throws IOException {
		return transferBytes(inputStream, outputStream, -1);
	}

	/**
	 * Read a size number of bytes from the inputstream and write them into a string in the outputstream.
	 *
	 * @param inputStream The inputStream.
	 * @param outputStream The outputstream.
	 * @param size the number of bytes to copy. If the size is negative or zero, it copy all the bytes from the inputstream.
	 * @return The total number of copy bytes.
	 * @throws IOException When an I/O error occurred.
	 */
	static int transferBytes(final InputStream inputStream, final OutputStream outputStream, final int size)
		throws IOException {
		final int bufferSize = size > 0 && size < READ_BUFFER_SIZE ? size : READ_BUFFER_SIZE;
		final byte[] buffer = new byte[bufferSize];

		int total = 0;
		int bytesRead = 0;

		while (inputStream.available() > 0 && (bytesRead = inputStream.read(buffer)) > 0) {
			final int bytesCopy = Math.min(bytesRead, READ_BUFFER_SIZE);

			outputStream.write(Arrays.copyOf(buffer, bytesCopy));
			outputStream.flush();

			total += bytesRead;

			if (size > 0 && total >= size) {
				return total;
			}
		}
		return total;
	}

	Connection getSshConnection() {
		return sshConnection;
	}

	Session getSshSession() {
		return sshSession;
	}
}
