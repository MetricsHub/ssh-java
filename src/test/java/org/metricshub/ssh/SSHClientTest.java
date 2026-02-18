package org.metricshub.ssh;

import com.trilead.ssh2.ChannelCondition;
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.SFTPv3Client;
import com.trilead.ssh2.SFTPv3FileAttributes;
import com.trilead.ssh2.Session;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

class SSHClientTest {

	private static final String HOSTNAME = "host";
	private static final String TEXT = "Hello World";

	@Test
	void testTransferBytesCopy() throws Exception {
		try (
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()
		) {
			Assertions.assertEquals(1, SshClient.transferBytes(byteArrayInputStream, byteArrayOutputStream, 1));
			Assertions.assertEquals("H", byteArrayOutputStream.toString());

			Assertions.assertEquals(2, SshClient.transferBytes(byteArrayInputStream, byteArrayOutputStream, 2));
			Assertions.assertEquals("Hel", byteArrayOutputStream.toString());

			Assertions.assertEquals(3, SshClient.transferBytes(byteArrayInputStream, byteArrayOutputStream, 3));
			Assertions.assertEquals("Hello ", byteArrayOutputStream.toString());

			Assertions.assertEquals(5, SshClient.transferBytes(byteArrayInputStream, byteArrayOutputStream, 10));
			Assertions.assertEquals(TEXT, byteArrayOutputStream.toString());
		}

		try (
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()
		) {
			Assertions.assertEquals(TEXT.length(), SshClient.transferBytes(byteArrayInputStream, byteArrayOutputStream, 0));
			Assertions.assertEquals(TEXT, byteArrayOutputStream.toString());
		}

		try (
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()
		) {
			Assertions.assertEquals(TEXT.length(), SshClient.transferBytes(byteArrayInputStream, byteArrayOutputStream, -1));
			Assertions.assertEquals(TEXT, byteArrayOutputStream.toString());
		}
	}

	@Test
	void testTransferAllBytes() throws Exception {
		try (
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()
		) {
			Assertions.assertEquals(TEXT.length(), SshClient.transferAllBytes(byteArrayInputStream, byteArrayOutputStream));
			Assertions.assertEquals(TEXT, byteArrayOutputStream.toString());
		}
	}

	@Test
	void testCheckIfConnected() {
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.checkIfConnected());

			Mockito.doReturn(Mockito.mock(Connection.class)).when(sshClient).getSshConnection();
			sshClient.checkIfConnected();
		}
	}

	@Test
	void testCheckIfAuthenticated() {
		final Connection sshConnection = Mockito.mock(Connection.class);

		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(false).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.checkIfAuthenticated());

			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();
			sshClient.checkIfAuthenticated();
		}
	}

	@Test
	void testCheckIfSessionOpened() {
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.checkIfSessionOpened());

			Mockito.doReturn(Mockito.mock(Session.class)).when(sshClient).getSshSession();
			sshClient.checkIfSessionOpened();
		}
	}

	@Test
	void testHasTimeoutSession() {
		Assertions.assertFalse(
			SshClient.hasTimeoutSession(ChannelCondition.STDOUT_DATA | ChannelCondition.EOF | ChannelCondition.CLOSED)
		);
		Assertions.assertTrue(SshClient.hasTimeoutSession(ChannelCondition.STDOUT_DATA | ChannelCondition.TIMEOUT));
	}

	@Test
	void testHasEndOfFileSession() {
		Assertions.assertFalse(
			SshClient.hasEndOfFileSession(ChannelCondition.STDOUT_DATA | ChannelCondition.TIMEOUT | ChannelCondition.CLOSED)
		);
		Assertions.assertTrue(SshClient.hasEndOfFileSession(ChannelCondition.STDOUT_DATA | ChannelCondition.EOF));
	}

	@Test
	void testHasSessionClosed() {
		Assertions.assertFalse(
			SshClient.hasSessionClosed(ChannelCondition.STDOUT_DATA | ChannelCondition.TIMEOUT | ChannelCondition.EOF)
		);
		Assertions.assertTrue(SshClient.hasSessionClosed(ChannelCondition.STDOUT_DATA | ChannelCondition.CLOSED));
	}

	@Test
	void testHasStdoutData() {
		Assertions.assertFalse(
			SshClient.hasStdoutData(ChannelCondition.STDERR_DATA | ChannelCondition.TIMEOUT | ChannelCondition.EOF)
		);
		Assertions.assertTrue(SshClient.hasStdoutData(ChannelCondition.STDOUT_DATA | ChannelCondition.CLOSED));
	}

	@Test
	void testHasStderrData() {
		Assertions.assertFalse(
			SshClient.hasStderrData(ChannelCondition.STDOUT_DATA | ChannelCondition.TIMEOUT | ChannelCondition.EOF)
		);
		Assertions.assertTrue(SshClient.hasStderrData(ChannelCondition.STDERR_DATA | ChannelCondition.CLOSED));
	}

	@Test
	void testOpenSession() throws Exception {
		final Connection sshConnection = Mockito.mock(Connection.class);
		final Session sshSession = Mockito.mock(Session.class);

		// Case not Connected
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.openSession());
		}

		// Case not authenticate
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(false).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.openSession());
		}

		// Case OK
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();
			Mockito.doReturn(sshSession).when(sshConnection).openSession();

			sshClient.openSession();

			Assertions.assertEquals(sshSession, sshClient.getSshSession());
		}
	}

	@Test
	void testOpenTerminal() throws Exception {
		final Connection sshConnection = Mockito.mock(Connection.class);
		final Session sshSession = Mockito.mock(Session.class);

		// Case not Connected
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();
			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.openTerminal());
		}

		// Case not authenticate
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(false).when(sshConnection).isAuthenticationComplete();

			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.openTerminal());
		}

		// case Session not opened
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.openTerminal());
		}

		// Case OK
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();
			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doNothing().when(sshSession).requestPTY("dumb", 10000, 24, 640, 480, new byte[] { 53, 0, 0, 0, 0, 0 });
			Mockito.doNothing().when(sshSession).startShell();

			sshClient.openTerminal();
		}
	}

	@Test
	void testWrite() throws Exception {
		final Connection sshConnection = Mockito.mock(Connection.class);
		final Session sshSession = Mockito.mock(Session.class);

		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfConnected();
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();
			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();

			sshClient.write(null);
		}

		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfConnected();
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();
			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();

			sshClient.write("");
		}

		// Case not Connected
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();
			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.write(TEXT));
		}

		// Case not authenticate
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(false).when(sshConnection).isAuthenticationComplete();

			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();
			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.write(TEXT));
		}

		// case Session not opened
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.write(TEXT));
		}

		// case charset = null
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME, (Charset) null))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.write(TEXT));
		}

		// case stdin = null
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.write(TEXT));
		}

		// case OK
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(byteArrayOutputStream).when(sshSession).getStdin();

			sshClient.write(TEXT);

			Assertions.assertEquals(TEXT, byteArrayOutputStream.toString());
		}
	}

	@Test
	void testRead() throws Exception {
		final Connection sshConnection = Mockito.mock(Connection.class);
		final Session sshSession = Mockito.mock(Session.class);

		// case timeout 0 or negative
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> sshClient.read(1, 0));
			Assertions.assertThrows(IllegalArgumentException.class, () -> sshClient.read(1, -1));
		}

		// Case not Connected
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();
			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.read(1, 5));
		}

		// Case not authenticate
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(false).when(sshConnection).isAuthenticationComplete();

			Mockito.verify(sshClient, Mockito.never()).checkIfSessionOpened();
			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.read(1, 5));
		}

		// case Session not opened
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.read(1, 5));
		}

		// case charset = null
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME, (Charset) null))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.read(1, 5));
		}

		// case stdout = null
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.read(1, 5));
		}

		// case stderr = null
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.read(1, 5));
		}

		// case timeout
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.TIMEOUT).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.empty(), sshClient.read(1, 5));
		}

		// case session closed
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.CLOSED).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.empty(), sshClient.read(1, 5));
		}

		// case EOF
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.EOF).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.empty(), sshClient.read(1, 5));
		}

		// case read 1 byte from Stout
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.STDOUT_DATA).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.of("H"), sshClient.read(1, 5));
		}

		// case read 1 byte from Stderr
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream("".getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("Err".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.STDERR_DATA).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.of("E"), sshClient.read(1, 5));
		}

		// case read Stdout + 3 bytes from Stderr
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("Error".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito
				.doReturn(ChannelCondition.STDOUT_DATA | ChannelCondition.STDERR_DATA)
				.when(sshClient)
				.waitForNewData(5000L);

			Assertions.assertEquals(Optional.of("Hello WorldErr"), sshClient.read(TEXT.length() + 3, 5));
		}

		// case read all only Stdout
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.STDOUT_DATA | ChannelCondition.EOF).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.of(TEXT), sshClient.read(0, 5));
		}

		// case read all only Stderr
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream("".getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("Error".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito.doReturn(ChannelCondition.STDERR_DATA | ChannelCondition.CLOSED).when(sshClient).waitForNewData(5000L);

			Assertions.assertEquals(Optional.of("Error"), sshClient.read(0, 5));
		}

		// case read All Stdout and Stderr
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final ByteArrayInputStream stdout = new ByteArrayInputStream(TEXT.getBytes());
			final ByteArrayInputStream stderr = new ByteArrayInputStream("Error".getBytes())
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Mockito.doReturn(sshSession).when(sshClient).getSshSession();
			Mockito.doReturn(stdout).when(sshSession).getStdout();
			Mockito.doReturn(stderr).when(sshSession).getStderr();
			Mockito
				.doReturn(ChannelCondition.STDOUT_DATA | ChannelCondition.STDERR_DATA)
				.when(sshClient)
				.waitForNewData(5000L);

			Assertions.assertEquals(Optional.of("Hello WorldError"), sshClient.read(0, 5));
		}
	}

	@Test
	void testFileSize() throws Exception {
		final Connection sshConnection = Mockito.mock(Connection.class);
		final String filePath = "/path/to/file.txt";

		// Case not Connected
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.verify(sshClient, Mockito.never()).checkIfAuthenticated();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.fileSize(filePath));
		}

		// Case not authenticated
		try (final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME))) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(false).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.fileSize(filePath));
		}

		// Case file does not exist (IOException)
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					Mockito.when(mock.stat(filePath)).thenThrow(new IOException("File not found"));
				}
			)
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertThrows(IOException.class, () -> sshClient.fileSize(filePath));
		}

		// Case file size is 0
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					final SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
					attributes.size = 0L;
					Mockito.when(mock.stat(filePath)).thenReturn(attributes);
				}
			)
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertEquals(0L, sshClient.fileSize(filePath));
		}

		// Case file size is small (100 bytes)
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					final SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
					attributes.size = 100L;
					Mockito.when(mock.stat(filePath)).thenReturn(attributes);
				}
			)
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertEquals(100L, sshClient.fileSize(filePath));
		}

		// Case file size is large (1GB)
		try (
			final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					final SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
					attributes.size = 1073741824L;
					Mockito.when(mock.stat(filePath)).thenReturn(attributes);
				}
			)
		) {
			Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
			Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();

			Assertions.assertEquals(1073741824L, sshClient.fileSize(filePath));
		}
	}
}
