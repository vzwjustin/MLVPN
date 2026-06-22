=========================
Fequently Asked Questions
=========================

How much mlvpn costs
====================
Free. mlvpn is licenced under the open source BSD licence.

Troubleshooting
===============

mlvpn does not launch
---------------------
Launch mlvpn manually in debug mode:
.. code-block:: sh

    mlvpn --user _mlvpn -c /etc/mlvpn.conf --debug -Dprotocol -v

Check your permissions:
.. code-block:: sh

    chmod 0600 /etc/mlvpn/mlvpn.conf
    chmod 0700 /etc/mlvpn/mlvpn_updown.sh
    chown root /etc/mlvpn/mlvpn.conf /etc/mlvpn/mlvpn_updown.sh

mlvpn does not create the tunnel interface
------------------------------------------
Follow `mlvpn does not launch`_.

QUIC handshake fails or never connects
--------------------------------------
Check that both ends use ``transport = "quic"`` and were built with
``./configure --enable-quic``. The ``password`` must match on client and server.

Run in debug mode with the QUIC log token:

.. code-block:: sh

    mlvpn --user _mlvpn -c /etc/mlvpn.conf --debug -Dquic -v

Look for ``QUIC transport enabled`` at startup and ``QUIC session established``
after the handshake. Firewall rules must allow UDP between the configured
``bindport`` / ``remoteport``.

The CI smoke test in ``scripts/ci/quic-smoke.sh`` exercises the same flow locally;
see ``scripts/ci/README.md``.

