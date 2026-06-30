"""Unit tests for components.imap_client.IMAPClient.

Tests cover connection management, email fetching, flag manipulation,
and graceful error handling. All IMAP operations are mocked via
unittest.mock.patch against imaplib.IMAP4_SSL.

Validates requirements: 1.1, 1.4, 1.5, 1.8, 1.9
"""

import imaplib
import socket
from unittest.mock import MagicMock, patch

import pytest

from components.imap_client import IMAPClient


@pytest.fixture
def client() -> IMAPClient:
    """Create an IMAPClient with test credentials."""
    return IMAPClient(
        host="imap.test.local",
        port=993,
        username="testuser",
        password="testpass",
        timeout=5.0,
    )


class TestConnect:
    """Tests for IMAPClient.connect()."""

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_successful_connection(self, mock_ssl_cls: MagicMock, client: IMAPClient) -> None:
        """Successful connect sets internal connection and authenticates."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_ssl_cls.return_value = mock_conn

        client.connect()

        mock_ssl_cls.assert_called_once_with(
            host="imap.test.local",
            port=993,
            timeout=5.0,
        )
        mock_conn.login.assert_called_once_with("testuser", "testpass")
        assert client.is_connected is True

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_connection_timeout(self, mock_ssl_cls: MagicMock, client: IMAPClient) -> None:
        """Socket timeout during connect logs warning, no crash."""
        mock_ssl_cls.side_effect = socket.timeout("Connection timed out")

        client.connect()

        assert client._connection is None
        assert client.is_connected is False

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_connection_auth_error(self, mock_ssl_cls: MagicMock, client: IMAPClient) -> None:
        """Authentication failure logs warning, no crash."""
        mock_conn = MagicMock()
        mock_conn.login.side_effect = imaplib.IMAP4.error("Authentication failed")
        mock_ssl_cls.return_value = mock_conn

        client.connect()

        assert client._connection is None
        assert client.is_connected is False

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_connection_os_error(self, mock_ssl_cls: MagicMock, client: IMAPClient) -> None:
        """OSError (network unreachable) logs warning, no crash."""
        mock_ssl_cls.side_effect = OSError("Network is unreachable")

        client.connect()

        assert client._connection is None
        assert client.is_connected is False


class TestFetchUnread:
    """Tests for IMAPClient.fetch_unread()."""

    def test_fetch_unread_returns_empty_when_not_connected(self, client: IMAPClient) -> None:
        """Returns empty list when no connection exists."""
        assert client.fetch_unread() == []

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_fetch_unread_multiple_messages(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Fetches multiple unread messages as raw bytes."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.select.return_value = ("OK", [b"3"])
        mock_conn.uid.side_effect = [
            # search call
            ("OK", [b"1 2 3"]),
            # fetch UID 1
            ("OK", [(b"1 (RFC822 {100})", b"raw email content 1"), b")"]),
            # fetch UID 2
            ("OK", [(b"2 (RFC822 {200})", b"raw email content 2"), b")"]),
            # fetch UID 3
            ("OK", [(b"3 (RFC822 {300})", b"raw email content 3"), b")"]),
        ]
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        messages = client.fetch_unread()

        assert len(messages) == 3
        assert messages[0] == b"raw email content 1"
        assert messages[1] == b"raw email content 2"
        assert messages[2] == b"raw email content 3"

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_fetch_unread_no_messages(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Returns empty list when inbox has no unread messages."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.select.return_value = ("OK", [b"0"])
        mock_conn.uid.return_value = ("OK", [b""])
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        messages = client.fetch_unread()

        assert messages == []

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_fetch_unread_handles_fetch_error_per_message(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Skips messages that fail to fetch, returns the rest."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.select.return_value = ("OK", [b"2"])
        mock_conn.uid.side_effect = [
            # search call
            ("OK", [b"1 2"]),
            # fetch UID 1 - fails
            Exception("Fetch failed"),
            # fetch UID 2 - succeeds
            ("OK", [(b"2 (RFC822 {200})", b"raw email content 2"), b")"]),
        ]
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        messages = client.fetch_unread()

        assert len(messages) == 1
        assert messages[0] == b"raw email content 2"


class TestMarkAsRead:
    """Tests for IMAPClient.mark_as_read()."""

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_mark_as_read_success(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Returns True when flag is set successfully."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.uid.return_value = ("OK", [b"1 (FLAGS (\\Seen))"])
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        result = client.mark_as_read("1")

        assert result is True
        mock_conn.uid.assert_called_with("store", "1", "+FLAGS", "\\Seen")

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_mark_as_read_failure_non_ok_status(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Returns False when server returns non-OK status."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.uid.return_value = ("NO", [b"Permission denied"])
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        result = client.mark_as_read("99")

        assert result is False

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_mark_as_read_failure_exception(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Returns False on IMAP error, no crash."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.uid.side_effect = imaplib.IMAP4.error("Store failed")
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        result = client.mark_as_read("5")

        assert result is False

    def test_mark_as_read_when_not_connected(self, client: IMAPClient) -> None:
        """Returns False when not connected."""
        result = client.mark_as_read("1")
        assert result is False


class TestDisconnect:
    """Tests for IMAPClient.disconnect()."""

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_disconnect_graceful_teardown(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Calls close and logout, sets connection to None."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.close.return_value = ("OK", [b"Closed"])
        mock_conn.logout.return_value = ("BYE", [b"Logging out"])
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        assert client.is_connected is True

        client.disconnect()

        mock_conn.close.assert_called_once()
        mock_conn.logout.assert_called_once()
        assert client._connection is None

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_disconnect_handles_close_error(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Disconnect still completes even if close() raises."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_conn.close.side_effect = imaplib.IMAP4.error("No mailbox selected")
        mock_conn.logout.return_value = ("BYE", [b"Logging out"])
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        client.disconnect()

        mock_conn.logout.assert_called_once()
        assert client._connection is None

    def test_disconnect_when_not_connected(self, client: IMAPClient) -> None:
        """Disconnect is a no-op when not connected."""
        client.disconnect()
        assert client._connection is None


class TestIsConnected:
    """Tests for IMAPClient.is_connected property."""

    def test_is_connected_false_when_no_connection(self, client: IMAPClient) -> None:
        """Returns False when _connection is None."""
        assert client.is_connected is False

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_is_connected_true_when_noop_succeeds(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Returns True when NOOP returns OK."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.return_value = ("OK", [b"Nothing"])
        mock_ssl_cls.return_value = mock_conn

        client.connect()
        assert client.is_connected is True

    @patch("components.imap_client.imaplib.IMAP4_SSL")
    def test_is_connected_false_when_noop_fails(
        self, mock_ssl_cls: MagicMock, client: IMAPClient
    ) -> None:
        """Returns False when NOOP raises, resets connection."""
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.noop.side_effect = imaplib.IMAP4.error("Connection lost")
        mock_ssl_cls.return_value = mock_conn

        # Manually set connection to simulate previously connected state
        client._connection = mock_conn

        assert client.is_connected is False
        assert client._connection is None

    def test_is_connected_false_after_noop_exception(self, client: IMAPClient) -> None:
        """NOOP exception sets _connection to None and returns False."""
        mock_conn = MagicMock()
        mock_conn.noop.side_effect = OSError("Connection reset")

        # Manually set the connection to simulate a previously connected state
        client._connection = mock_conn

        assert client.is_connected is False
        assert client._connection is None
