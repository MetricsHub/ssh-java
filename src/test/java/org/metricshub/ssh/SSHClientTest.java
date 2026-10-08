package org.metricshub.ssh;

import com.trilead.ssh2.ChannelCondition;
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.SFTPException;
import com.trilead.ssh2.SFTPv3Client;
import com.trilead.ssh2.SFTPv3DirectoryEntry;
import com.trilead.ssh2.SFTPv3FileAttributes;
import com.trilead.ssh2.Session;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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

	private static final int REGULAR_FILE = 0100644;
	private static final int DIRECTORY = 0040755;
	private static final int SYMBOLIC_LINK = 0120777;
	private static final int CHARACTER_DEVICE = 0020666;
	private static final int BLOCK_DEVICE = 0060660;
	private static final int SOCKET = 0140755;

	private static SFTPv3FileAttributes attributes(final int permissions, final long size, final long mtime) {
		final SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
		attributes.permissions = permissions;
		attributes.size = size;
		attributes.mtime = mtime;
		return attributes;
	}

	private static SFTPv3DirectoryEntry entry(final String filename, final int permissions) {
		return entry(filename, permissions, 0, 0);
	}

	private static SFTPv3DirectoryEntry entry(
		final String filename,
		final int permissions,
		final long size,
		final long mtime
	) {
		final SFTPv3DirectoryEntry entry = new SFTPv3DirectoryEntry();
		entry.filename = filename;
		entry.attributes = attributes(permissions, size, mtime);
		return entry;
	}

	private static SshClient authenticatedClient() {
		final Connection sshConnection = Mockito.mock(Connection.class);
		Mockito.doReturn(true).when(sshConnection).isAuthenticationComplete();
		final SshClient sshClient = Mockito.spy(new SshClient(HOSTNAME));
		Mockito.doReturn(sshConnection).when(sshClient).getSshConnection();
		return sshClient;
	}

	private static SFTPException noSuchFile() throws Exception {
		// The constructor is package-private: the server reports SSH_FX_NO_SUCH_FILE (2)
		final Constructor<SFTPException> constructor = SFTPException.class.getDeclaredConstructor(String.class, int.class);
		constructor.setAccessible(true);
		return constructor.newInstance("No such file", 2);
	}

	private static List<String> paths(final List<SshClient.FileEntry> entries) {
		final List<String> paths = new ArrayList<>();
		for (SshClient.FileEntry entry : entries) {
			paths.add(entry.path);
		}
		return paths;
	}

	@Test
	void testListFiles() throws Exception {
		final SFTPException noSuchFile = noSuchFile();
		final List<SFTPv3DirectoryEntry> logs = Arrays.asList(
			entry(".", DIRECTORY),
			entry("..", DIRECTORY),
			entry("app.log", REGULAR_FILE, 100, 1000),
			entry(" my app;1.LOG ", REGULAR_FILE, 200, 2000),
			entry("link.log", SYMBOLIC_LINK),
			entry("dangling.log", SYMBOLIC_LINK),
			entry("dirlink.log", SYMBOLIC_LINK),
			entry("unrelated.lnk", SYMBOLIC_LINK),
			entry("tty.log", CHARACTER_DEVICE),
			entry("disk.log", BLOCK_DEVICE),
			entry("socket.log", SOCKET),
			entry("notes.txt", REGULAR_FILE, 50, 500),
			entry("sub", DIRECTORY)
		);

		// Directory with a trailing slash, no subfolders
		try (
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					Mockito.when(mock.ls("/logs/")).thenReturn(logs);
					Mockito.when(mock.stat("/logs/link.log")).thenReturn(attributes(REGULAR_FILE, 300, 3000));
					Mockito.when(mock.stat("/logs/dangling.log")).thenThrow(noSuchFile);
					Mockito.when(mock.stat("/logs/dirlink.log")).thenReturn(attributes(DIRECTORY, 0, 0));
				}
			)
		) {
			// Case-insensitive mask matched with find(); names are kept verbatim (spaces, semicolon)
			final List<SshClient.FileEntry> entries = authenticatedClient().listFiles("/logs/", "\\.log", false);

			Assertions.assertEquals(Arrays.asList("/logs/app.log", "/logs/ my app;1.LOG ", "/logs/link.log"), paths(entries));
			Assertions.assertEquals(100, entries.get(0).size);
			Assertions.assertEquals(1000, entries.get(0).mtime);
			Assertions.assertEquals(200, entries.get(1).size);
			// A symbolic link carries the size and modification time of its target
			Assertions.assertEquals(300, entries.get(2).size);
			Assertions.assertEquals(3000, entries.get(2).mtime);

			final SFTPv3Client sftpClient = mockedConstruction.constructed().get(0);
			// A link whose name does not match is never followed, a subfolder is not listed
			Mockito.verify(sftpClient, Mockito.never()).stat("/logs/unrelated.lnk");
			Mockito.verify(sftpClient, Mockito.never()).ls("/logs/sub");
			Mockito.verify(sftpClient).close();
		}

		// Subfolders, no mask
		try (
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					Mockito
						.when(mock.ls("/"))
						.thenReturn(
							Arrays.asList(
								entry(".", DIRECTORY),
								entry("..", DIRECTORY),
								entry("top.txt", REGULAR_FILE, 1, 10),
								entry("sub", DIRECTORY),
								entry("sublink", SYMBOLIC_LINK)
							)
						);
					Mockito.when(mock.ls("/sub")).thenReturn(Arrays.asList(entry("nested.log", REGULAR_FILE, 2, 20)));
					Mockito.when(mock.stat("/sublink")).thenReturn(attributes(DIRECTORY, 0, 0));
				}
			)
		) {
			Assertions.assertEquals(
				Arrays.asList("/top.txt", "/sub/nested.log"),
				paths(authenticatedClient().listFiles("/", null, true))
			);
			final SFTPv3Client sftpClient = mockedConstruction.constructed().get(0);
			// Neither "." nor ".." nor a symbolic link to a directory is descended into
			Mockito.verify(sftpClient, Mockito.never()).ls("/.");
			Mockito.verify(sftpClient, Mockito.never()).ls("/..");
			Mockito.verify(sftpClient, Mockito.never()).ls("/sublink");
			Mockito.verify(sftpClient).close();
		}

		// The SFTP client is closed when the listing fails
		try (
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> Mockito.when(mock.ls("/missing")).thenThrow(noSuchFile)
			)
		) {
			final SshClient sshClient = authenticatedClient();
			Assertions.assertThrows(SFTPException.class, () -> sshClient.listFiles("/missing", null, false));
			Mockito.verify(mockedConstruction.constructed().get(0)).close();
		}

		// Not authenticated
		try (final SshClient sshClient = new SshClient(HOSTNAME)) {
			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.listFiles("/logs", null, false));
		}
	}

	@Test
	void testListSubdirectories() throws Exception {
		final SFTPException noSuchFile = noSuchFile();
		final List<SFTPv3DirectoryEntry> opt = Arrays.asList(
			entry(".", DIRECTORY),
			entry("..", DIRECTORY),
			entry("node1", DIRECTORY),
			entry("Node2", SYMBOLIC_LINK),
			entry("node3", SYMBOLIC_LINK),
			entry("node4", SYMBOLIC_LINK),
			entry("node5", REGULAR_FILE),
			entry("other", DIRECTORY),
			entry("otherlink", SYMBOLIC_LINK)
		);

		try (
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> {
					Mockito.when(mock.ls("/opt")).thenReturn(opt);
					Mockito.when(mock.ls("/")).thenReturn(opt);
					Mockito.when(mock.stat(Mockito.endsWith("Node2"))).thenReturn(attributes(DIRECTORY, 0, 0));
					Mockito.when(mock.stat(Mockito.endsWith("node3"))).thenThrow(noSuchFile);
					Mockito.when(mock.stat(Mockito.endsWith("node4"))).thenReturn(attributes(REGULAR_FILE, 0, 0));
					Mockito.when(mock.stat(Mockito.endsWith("otherlink"))).thenReturn(attributes(DIRECTORY, 0, 0));
				}
			)
		) {
			final SshClient sshClient = authenticatedClient();

			// Case-insensitive mask; a link to a directory is listed, a dangling link or a link to a file is not
			Assertions.assertEquals(Arrays.asList("/opt/node1", "/opt/Node2"), sshClient.listSubdirectories("/opt", "^node"));
			Mockito.verify(mockedConstruction.constructed().get(0), Mockito.never()).stat("/opt/otherlink");
			Mockito.verify(mockedConstruction.constructed().get(0)).close();

			// No mask, root directory
			Assertions.assertEquals(
				Arrays.asList("/node1", "/Node2", "/other", "/otherlink"),
				sshClient.listSubdirectories("/", "")
			);
		}

		// The SFTP client is closed when the listing fails
		try (
			final MockedConstruction<SFTPv3Client> mockedConstruction = Mockito.mockConstruction(
				SFTPv3Client.class,
				(mock, context) -> Mockito.when(mock.ls("/missing")).thenThrow(noSuchFile)
			)
		) {
			final SshClient sshClient = authenticatedClient();
			Assertions.assertThrows(SFTPException.class, () -> sshClient.listSubdirectories("/missing", null));
			Mockito.verify(mockedConstruction.constructed().get(0)).close();
		}

		// Not authenticated
		try (final SshClient sshClient = new SshClient(HOSTNAME)) {
			Assertions.assertThrows(IllegalStateException.class, () -> sshClient.listSubdirectories("/opt", null));
		}
	}
}
