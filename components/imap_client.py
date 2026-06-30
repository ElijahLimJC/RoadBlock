"""IMAP Client component for email fetching with SSL/TLS.

This module wraps Python's imaplib for IMAP operations including connection
management, unread email fetching, and message flag manipulation. All operations
are exception-isolated to prevent crash propagation into the polling loop.
"""

import imaplib
import logging
import os
import socket

logger = logging.getLogger(__name__)


class IMAPClient:
    """IMAP connection wrapper with SSL/TLS and fetch operations.

    Connects to an IMAP server using credentials from environment variables,
    fetches unread emails as raw bytes, and supports marking messages as read.
    All failures are logged at warning level without raising exceptions to the
    caller.

    Attributes:
        host: IMAP server hostname.
        port: IMAP server port (default 993).
        username: Authentication username.
        password: Authentication password.
        timeout: Connection timeout in seconds.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Initialize IMAPClient with connection parameters.

        Loads connection details from environment variables if not provided
        directly. Environment variables: IMAP_HOST, IMAP_PORT (default 993),
        IMAP_USERNAME, IMAP_PASSWORD.

        Args:
            host: IMAP server hostname. Falls back to IMAP_HOST env var.
            port: IMAP server port. Falls back to IMAP_PORT env var (default 993).
            username: Auth username. Falls back to IMAP_USERNAME env var.
            password: Auth password. Falls back to IMAP_PASSWORD env var.
            timeout: Connection timeout in seconds (default 10.0).
        """
        self.host = host or os.environ.get("IMAP_HOST", "")
        self.port = port or int(os.environ.get("IMAP_PORT", "993"))
        self.username = username or os.environ.get("IMAP_USERNAME", "")
        self.password = password or os.environ.get("IMAP_PASSWORD", "")
        self.timeout = timeout
        self._connection: imaplib.IMAP4_SSL | None = None
        self._baseline_uid: int = 0
        self._baseline_set: bool = False

    def connect(self) -> None:
        """Establish SSL/TLS connection and authenticate.

        Creates an IMAP4_SSL connection to the configured host/port with the
        specified timeout, then authenticates with username/password. On failure,
        logs at warning level and does not propagate the exception.
        """
        try:
            self._connection = imaplib.IMAP4_SSL(
                host=self.host,
                port=self.port,
                timeout=self.timeout,
            )
            self._connection.login(self.username, self.password)
            logger.info("IMAP connected to %s:%d", self.host, self.port)
        except (imaplib.IMAP4.error, OSError, socket.timeout) as e:
            logger.warning("IMAP connection failed: %s", e)
            self._connection = None
        except Exception as e:
            logger.warning("IMAP unexpected connection error: %s", e)
            self._connection = None

    def fetch_unread(self) -> list[tuple[str, bytes]]:
        """Fetch new unread email bytes from inbox with their UIDs.

        On first call, records the current highest UID as a baseline and
        returns nothing (skips pre-existing emails). Subsequent calls only
        return emails with UIDs above the baseline that are UNSEEN.

        Returns:
            List of (uid, raw_bytes) tuples for new unread messages. Empty
            list if not connected or on any fetch error.
        """
        if not self.is_connected:
            logger.warning("Cannot fetch: IMAP client not connected")
            return []

        try:
            assert self._connection is not None
            self._connection.select("INBOX")

            # On first poll, establish baseline UID (skip all existing emails)
            if not self._baseline_set:
                status, data = self._connection.uid("search", None, "ALL")
                if status == "OK" and data and data[0]:
                    all_uids = data[0].split()
                    if all_uids:
                        self._baseline_uid = int(all_uids[-1])
                self._baseline_set = True
                logger.info(
                    "IMAP baseline set at UID %d (skipping existing emails)",
                    self._baseline_uid,
                )
                return []

            # Search for UNSEEN messages with UID greater than baseline
            # Use separate search criteria (some servers don't support combined string)
            search_criteria = f"UID {self._baseline_uid + 1}:*"
            status, data = self._connection.uid("search", None, "UNSEEN", search_criteria)
            if status != "OK" or not data or not data[0]:
                return []

            uids = data[0].split()
            messages: list[tuple[str, bytes]] = []

            for uid in uids:
                uid_int = int(uid)
                if uid_int <= self._baseline_uid:
                    continue

                try:
                    status, msg_data = self._connection.uid(
                        "fetch", uid, "(RFC822)"
                    )
                    if status == "OK" and msg_data and msg_data[0] is not None:
                        if isinstance(msg_data[0], tuple) and len(msg_data[0]) >= 2:
                            messages.append((uid.decode(), msg_data[0][1]))
                            # Update baseline to this UID
                            if uid_int > self._baseline_uid:
                                self._baseline_uid = uid_int
                except Exception as e:
                    logger.warning("Failed to fetch UID %s: %s", uid, e)
                    continue

            return messages

        except (imaplib.IMAP4.error, OSError, socket.timeout) as e:
            logger.warning("IMAP fetch_unread failed: %s", e)
            return []
        except Exception as e:
            logger.warning("IMAP unexpected fetch error: %s", e)
            return []

    def mark_as_read(self, message_uid: str) -> bool:
        """Mark a message as read by setting the \\Seen flag.

        Args:
            message_uid: The UID of the message to mark as read.

        Returns:
            True if the flag was set successfully, False otherwise.
        """
        if not self.is_connected:
            logger.warning("Cannot mark as read: IMAP client not connected")
            return False

        try:
            assert self._connection is not None
            status, _ = self._connection.uid(
                "store", message_uid, "+FLAGS", "\\Seen"
            )
            if status == "OK":
                return True
            logger.warning(
                "IMAP mark_as_read returned non-OK status for UID %s: %s",
                message_uid,
                status,
            )
            return False
        except (imaplib.IMAP4.error, OSError, socket.timeout) as e:
            logger.warning("IMAP mark_as_read failed for UID %s: %s", message_uid, e)
            return False
        except Exception as e:
            logger.warning(
                "IMAP unexpected mark_as_read error for UID %s: %s", message_uid, e
            )
            return False

    def disconnect(self) -> None:
        """Gracefully close IMAP connection.

        Attempts to close the selected mailbox and logout. Logs at warning
        on failure but does not propagate exceptions.
        """
        if self._connection is None:
            return

        try:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection.logout()
            logger.info("IMAP disconnected from %s:%d", self.host, self.port)
        except (imaplib.IMAP4.error, OSError) as e:
            logger.warning("IMAP disconnect error: %s", e)
        except Exception as e:
            logger.warning("IMAP unexpected disconnect error: %s", e)
        finally:
            self._connection = None

    @property
    def is_connected(self) -> bool:
        """Connection status check.

        Returns:
            True if a connection object exists and responds to NOOP,
            False otherwise.
        """
        if self._connection is None:
            return False
        try:
            status, _ = self._connection.noop()
            return status == "OK"
        except Exception:
            self._connection = None
            return False
