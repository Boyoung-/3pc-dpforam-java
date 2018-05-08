package communication;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.bouncycastle.util.Arrays;

import crypto.SimpleAES;
import struct.Global;
import util.Array64;
import util.Bandwidth;
import util.Util;

/**
 * Basic Usage
 * 
 * 1. Call {@link #start(int)} or {@link #connect(InetSocketAddress)} to
 * initiate a connection 2. Wait for {@link #getState()} to return
 * {@link #STATE_CONNECTED} 3. {@link #write(byte[])} and {@link #read()}
 * messages. 4. Close the connection with {@link #stop()}. NOTE: This may
 * invalidate unread data
 * 
 * Alternatively, you can always call start. And the first side of the
 * connection to call connect will win.
 */
public class Communication {

	public static boolean D = false;

	// Constants that indicate the current connection state
	public static final int STATE_NONE = 0; // we're doing nothing
	public static final int STATE_LISTEN = 1; // now listening for incoming
												// connections
	public static final int STATE_CONNECTING = 2; // now initiating an outgoing
													// connection
	public static final int STATE_CONNECTED = 3; // now connected to a remote
													// device
	public static final int STATE_STOPPED = 4; // we're shutting things down
	public static final int STATE_RETRY = 5; // we are going to retry, but first
												// we listen

	private AcceptThread mSecureAcceptThread;
	private ConnectThread mConnectThread;
	private ConnectedThread mConnectedThread;

	// Maximum reconnect attempts
	private static final int MAX_RETRY = 2;

	/***********************
	 * Private Members
	 **********************/
	// Current number of reconnect attempts
	private int mNumTries;
	private int mPort = 0;

	private boolean acceptMode = false;

	protected int mState;
	protected InetSocketAddress mAddress;

	private static SimpleAES aes = new SimpleAES();

	public Communication() {
		mState = STATE_NONE;
	}

	public void setTcpNoDelay(boolean on) {
		if (mConnectedThread != null)
			mConnectedThread.setTcpNoDelay(on);
	}

	/**
	 * Set the current state of the connection
	 * 
	 * @param state
	 *            An integer defining the current connection state
	 */
	protected synchronized void setState(int state) {
		if (D)
			Util.debug("setState() " + mState + " -> " + state);
		mState = state;
	}

	/**
	 * Return the current connection state.
	 */
	public synchronized int getState() {
		return mState;
	}

	/**
	 * Start the communication service. Specifically start AcceptThread to begin a
	 * session in listening (server) mode.
	 */
	public synchronized void start(int port) {
		if (D)
			Util.debug("start");

		acceptMode = true;

		startAcceptThread(port);

		mPort = port;
		mNumTries = 0;

		setState(STATE_LISTEN);
	}

	private synchronized void startAcceptThread(int port) {
		// Cancel any thread attempting to make a connection
		if (mConnectThread != null) {
			mConnectThread.cancel();
			mConnectThread = null;
		}

		// Cancel any thread currently running a connection
		if (mConnectedThread != null) {
			mConnectedThread.cancel();
			mConnectedThread = null;
		}

		// Start the thread to listen on a ServerSocket
		if (mSecureAcceptThread == null) {
			mSecureAcceptThread = new AcceptThread(port);
			mSecureAcceptThread.start();
		}
	}

	protected synchronized void retry() {
		if (D)
			Util.debug("retry");

		if (D)
			Util.debug("Retrying in state: " + getState());

		if (mState == STATE_CONNECTED)
			return;

		// TODO: Does this logic belong here
		if (mNumTries >= MAX_RETRY) {
			signalFailed();

			if (acceptMode)
				start(mPort);
			return;
		}

		startAcceptThread(mPort);

		setState(STATE_RETRY);

		int sleep = (int) (Math.random() * 1000 + 100);
		if (D)
			Util.debug("Sleeping: " + sleep);
		try {
			Thread.sleep(sleep);
		} catch (InterruptedException e) {
			Util.debug("Sleep interupted");
		} // TODO: This may block the main thread?

		if (D)
			Util.debug("Waking up: " + getState());

		// TODO: make this less strict
		if (mState != STATE_CONNECTING && mState != STATE_CONNECTED && mConnectedThread == null
				&& mConnectThread == null)
			connect(mAddress);
	}

	/**
	 * Start the ConnectThread to initiate a connection to a remote device.
	 * 
	 * @param address
	 *            The address of the server
	 * @param secure
	 *            Socket Security type - Secure (true) , Insecure (false)
	 */
	public synchronized void connect(InetSocketAddress address) {
		if (D)
			Util.disp("connect to: " + address);

		// Don't throw out connections if we are already connected
		/*
		 * if (mState == STATE_CONNECTING || mConnectedThread != null) { return; }
		 */

		mNumTries++;
		mAddress = address;

		// Cancel any thread attempting to make a connection
		if (mState == STATE_CONNECTING) {
			if (mConnectThread != null) {
				mConnectThread.cancel();
				mConnectThread = null;
			}
		}

		// Cancel any thread currently running a connection
		if (mConnectedThread != null) {
			mConnectedThread.cancel();
			mConnectedThread = null;
		}

		// Start the thread to connect with the given device
		mConnectThread = new ConnectThread(address);
		mConnectThread.start();
		setState(STATE_CONNECTING);
	}

	/**
	 * Start the ConnectedThread to begin managing a connection
	 * 
	 * @param socket
	 *            The Socket on which the connection was made
	 */
	public synchronized void connected(Socket socket) {
		if (D)
			Util.debug("connected");

		// Cancel the thread that completed the connection
		if (mConnectThread != null) {
			mConnectThread.cancel();
			mConnectThread = null;
		}

		// Cancel any thread currently running a connection
		if (mConnectedThread != null) {
			mConnectedThread.cancel();
			mConnectedThread = null;
		}

		// Cancel the accept thread because we only want to connect to one
		// device
		if (mSecureAcceptThread != null) {
			mSecureAcceptThread.cancel();
			mSecureAcceptThread = null;
		}

		// Start the thread to manage the connection and perform transmissions
		mConnectedThread = new ConnectedThread(socket);
		mConnectedThread.start();

		setState(STATE_CONNECTED);
	}

	protected void connectionFailed() {
		Util.error("Connection to the device failed");

		// Start the service over to restart listening mode
		if (getState() != STATE_STOPPED)
			retry();
	}

	/**
	 * Indicate that the connection was lost and notify the UI Activity.
	 */
	protected void connectionLost() {
		if (D)
			Util.error("Connection to the device lost");

		// Start the service over to restart listening mode
		if (getState() != STATE_STOPPED && acceptMode) {
			start(mPort);
		}
	}

	protected void signalFailed() {
		// TODO:
	}

	/**
	 * Stop all threads
	 */
	public synchronized void stop() {
		if (D)
			Util.debug("stop");
		setState(STATE_STOPPED);

		if (mConnectedThread != null) {
			mConnectedThread.cancel();
			mConnectedThread = null;
		}

		if (mConnectThread != null) {
			mConnectThread.cancel();
			mConnectThread = null;
		}

		if (mSecureAcceptThread != null) {
			mSecureAcceptThread.cancel();
			mSecureAcceptThread = null;
		}
	}

	/**
	 * Write to the ConnectedThread in an unsynchronized manner
	 * 
	 * This does not add message boundries!!
	 * 
	 * @param out
	 *            The bytes to write
	 * @see ConnectedThread#write(byte[])
	 */
	public void write(byte[] out) {
		// Create temporary object
		ConnectedThread r;
		// Synchronize a copy of the ConnectedThread
		synchronized (this) {
			if (mState != STATE_CONNECTED)
				return;
			r = mConnectedThread;
		}
		// Perform the write unsynchronized
		if (Global.linkEnc)
			out = aes.encrypt(out);
		r.write(out);
	}

	public void write(Bandwidth bandwidth, byte[] out) {
		write(out);

		if (Global.bandSwitch)
			bandwidth.add(out.length);
	}

	/**
	 * Write a length encoded byte array.
	 * 
	 * @param out
	 */
	public void writeLengthEncoded(byte[] out) {
		write("" + out.length);
		write(out);
	}

	public <T> void write(T out) {
		write(SerializationUtils.serialize((Serializable) out));
	}

	public <T> void write(Bandwidth bandwidth, T out) {
		write(bandwidth, SerializationUtils.serialize((Serializable) out));
	}

	public void write(Array64<byte[]> array) {
		int len = array.numChunks();
		byte[] size_bytes = BigInteger.valueOf(array.size()).toByteArray();
		byte[] len_bytes = Util.intToBytes(len);
		write(ArrayUtils.addAll(size_bytes, len_bytes));
		for (int i = 0; i < len; i++) {
			Object[] b = array.getChunk(i);
			write(b);
		}
	}

	public void write(Bandwidth bandwidth, Array64<byte[]> array) {
		int len = array.numChunks();
		byte[] size_bytes = BigInteger.valueOf(array.size()).toByteArray();
		byte[] len_bytes = Util.intToBytes(len);
		write(bandwidth, ArrayUtils.addAll(size_bytes, len_bytes));
		for (int i = 0; i < len; i++) {
			Object[] b = array.getChunk(i);
			write(bandwidth, b);
		}
	}

	public void write(BigInteger b) {
		write(b.toByteArray());
	}

	public void write(Bandwidth bandwidth, BigInteger b) {
		write(bandwidth, b.toByteArray());
	}

	public void write(int n) {
		write(BigInteger.valueOf(n));
	}

	public void write(Bandwidth bandwidth, int n) {
		write(bandwidth, BigInteger.valueOf(n));
	}

	public void write(long n) {
		write(BigInteger.valueOf(n));
	}

	public void write(Bandwidth bandwidth, long n) {
		write(bandwidth, BigInteger.valueOf(n));
	}

	public void write(byte[][] arr) {
		write(ComUtil.serialize(arr));
	}

	public void write(Bandwidth bandwidth, byte[][] arr) {
		write(bandwidth, ComUtil.serialize(arr));
	}

	public void write(byte[][][] arr) {
		write(ComUtil.serialize(arr));
	}

	public void write(Bandwidth bandwidth, byte[][][] arr) {
		write(bandwidth, ComUtil.serialize(arr));
	}

	public void write(int[] arr) {
		write(ComUtil.serialize(arr));
	}

	public void write(Bandwidth bandwidth, int[] arr) {
		write(bandwidth, ComUtil.serialize(arr));
	}

	public void write(int[][] arr) {
		write(ComUtil.serialize(arr));
	}

	public void write(Bandwidth bandwidth, int[][] arr) {
		write(bandwidth, ComUtil.serialize(arr));
	}

	public void write(ArrayList<byte[]> arr) {
		write(ComUtil.serialize(arr));
	}

	public void write(Bandwidth bandwidth, ArrayList<byte[]> arr) {
		write(bandwidth, ComUtil.serialize(arr));
	}

	public static final Charset defaultCharset = Charset.forName("ASCII");

	public void write(String buffer) {
		write(buffer, defaultCharset);
	}

	/*
	 * This was added to allow backwords compaitibility with older versions which
	 * used the default charset (usually utf-8) instead of asc-ii. This is almost
	 * never what we want to do
	 */
	public void write(String buffer, Charset charset) {
		write(buffer.getBytes(charset));
		if (D)
			Util.debug("Write: " + buffer);
	}

	/**
	 * Read a string from Connected Thread
	 * 
	 * @see #read()
	 */
	public String readString() {
		return new String(read());
	}

	/**
	 * Read from the ConnectedThread in an unsynchronized manner Note, this is a
	 * blocking call
	 * 
	 * @return the bytes read
	 * @see ConnectedThread#read()
	 */
	public byte[] read() {
		// Create temporary object
		ConnectedThread r;
		// Synchronize a copy of the ConnectedThread
		synchronized (this) {
			if (mState != STATE_CONNECTED)
				return null;
			r = mConnectedThread;
		}

		// Perform the read unsynchronized and parse
		byte[] readMessage = r.read();
		if (Global.linkEnc)
			readMessage = aes.decrypt(readMessage);

		if (D)
			Util.debug("Read: " + new String(readMessage));
		return readMessage;
	}

	/**
	 * Read a specific number of bytes from the ConnectedThread in an unsynchronized
	 * manner Note, this is a blocking call
	 * 
	 * @return the bytes read
	 * @see ConnectedThread#read()
	 */
	public byte[] readLengthEncoded() {
		int len = Integer.parseInt(readString());
		ArrayList<byte[]> bytes = new ArrayList<byte[]>();
		byte[] data = read();
		if (data.length != len) {
			bytes.add(data);
			data = read();
		}

		byte[] total = new byte[len];
		int offset = 0;
		for (byte[] b : bytes) {
			for (int i = 0; i < b.length; i++) {
				total[offset++] = b[i];
			}
		}

		return total;
	}

	public <T> T readObject() {
		T object = SerializationUtils.deserialize(read());
		return object;
	}

	public Array64<byte[]> readArray64ByteArray() {
		byte[] metadata = read();
		int midpoint = metadata.length - 4;
		byte[] size_bytes = Arrays.copyOfRange(metadata, 0, midpoint);
		byte[] len_bytes = Arrays.copyOfRange(metadata, midpoint, metadata.length);
		long size = new BigInteger(1, size_bytes).longValue();
		int len = Util.bytesToInt(len_bytes);
		Object[][] data = new Object[len][];
		for (int i = 0; i < len; i++)
			data[i] = this.readObject();
		return new Array64<byte[]>(size, data);
	}

	public BigInteger readBigInteger() {
		return new BigInteger(read());
	}

	public int readInt() {
		return readBigInteger().intValue();
	}

	public long readLong() {
		return readBigInteger().longValue();
	}

	public byte[][] readDoubleByteArray() {
		return ComUtil.toDoubleByteArray(read());
	}

	public byte[][][] readTripleByteArray() {
		return ComUtil.toTripleByteArray(read());
	}

	public int[] readIntArray() {
		return ComUtil.toIntArray(read());
	}

	public int[][] readDoubleIntArray() {
		return ComUtil.toDoubleIntArray(read());
	}

	public ArrayList<byte[]> readArrayList() {
		return ComUtil.toArrayList(read());
	}

	/**
	 * This thread runs while listening for incoming connections. It behaves like a
	 * server-side client. It runs until a connection is accepted (or until
	 * cancelled).
	 */
	private class AcceptThread extends Thread {
		// The local server socket
		private final ServerSocket mmServerSocket;

		public AcceptThread(int port) {
			ServerSocket tmp = null;
			try {
				tmp = new ServerSocket(port);
			} catch (IOException e) {
				Util.error("ServerSocket unable to start", e);
			}

			mmServerSocket = tmp;
		}

		public void run() {
			if (D)
				Util.disp("BEGIN mAcceptThread ");
			setName("AcceptThread");

			Socket socket = null;

			// Listen to the server socket if we're not connected
			while (mState != STATE_CONNECTED) {
				try {
					// This is a blocking call and will only return on a
					// successful connection or an exception
					socket = mmServerSocket.accept();
					// socket.setTcpNoDelay(true);
				} catch (IOException e) {
					Util.error("accept() failed", e);
					break;
				}

				// If a connection was accepted
				if (socket != null) {
					synchronized (Communication.this) {
						switch (mState) {
						case STATE_LISTEN:
						case STATE_CONNECTING:
							// Situation normal. Start the connected thread.
							connected(socket);
							break;
						case STATE_NONE:
						case STATE_CONNECTED:
							// Either not ready or already connected.
							// Terminate new socket.
							try {
								socket.close();
							} catch (IOException e) {
								Util.error("Could not close unwanted socket", e);
							}

							// TODO: Should we really be returning here?
							return;
						}
					}
				}
			}
			if (D)
				Util.disp("END mAcceptThread");

		}

		public void cancel() {
			if (D)
				Util.debug("AcceptThread canceled " + this);
			try {
				mmServerSocket.close();
			} catch (IOException e) {
				Util.error("close() of server failed", e);
			}
		}
	}

	/**
	 * This thread runs while attempting to make an outgoing connection with a
	 * device. It runs straight through; the connection either succeeds or fails.
	 */
	private class ConnectThread extends Thread {
		private final Socket mmSocket;
		private final InetSocketAddress mmAddress;

		public ConnectThread(InetSocketAddress address) {
			mmAddress = address;

			mmSocket = new Socket();
			/*
			 * try { mmSocket.setTcpNoDelay(true); } catch (SocketException e) {
			 * e.printStackTrace(); }
			 */
		}

		public void run() {
			Util.debug("BEGIN mConnectThread");
			setName("ConnectThread");

			try {
				// This is a blocking call and will only return on a
				// successful connection or an exception
				mmSocket.connect(mmAddress);
			} catch (IOException e) {
				// Close the socket
				try {
					mmSocket.close();
				} catch (IOException e2) {
					Util.error("unable to close() socket during connection failure", e2);
				}
				connectionFailed();
				return;
			}

			// Reset the ConnectThread because we're done
			synchronized (Communication.this) {
				mConnectThread = null;
			}

			// Start the connected thread
			connected(mmSocket);
		}

		public void cancel() {
			try {
				mmSocket.close();
			} catch (IOException e) {
				Util.error("close() of connect socket failed", e);
			}
		}
	}

	/**
	 * This thread runs during a connection with a remote device. It handles all
	 * incoming and outgoing transmissions.
	 */
	private class ConnectedThread extends Thread {
		private final Socket mmSocket;
		private final DataInputStream mmInStream;
		private final DataOutputStream mmOutStream;

		private BlockingQueue<byte[]> mMessageBuffer;

		public ConnectedThread(Socket socket) {
			Util.debug("create ConnectedThread");
			mmSocket = socket;
			DataInputStream tmpIn = null;
			DataOutputStream tmpOut = null;
			// TODO: add a capacity here to prevent doS
			mMessageBuffer = new LinkedBlockingQueue<byte[]>();

			// Get the Socket input and output streams
			try {
				tmpIn = new DataInputStream(socket.getInputStream());
				tmpOut = new DataOutputStream(socket.getOutputStream());

			} catch (StreamCorruptedException e) {
				Util.error("object streams corrupt", e);
			} catch (IOException e) {
				Util.error("temp sockets not created", e);
			}

			mmInStream = tmpIn;
			mmOutStream = tmpOut;

		}

		public void setTcpNoDelay(boolean on) {
			if (mmSocket != null)
				try {
					mmSocket.setTcpNoDelay(on);
				} catch (SocketException e) {
					e.printStackTrace();
				}
		}

		/**
		 * Read from the ConnectedThread in an unsynchronized manner
		 * 
		 * This is a blocking call and will only return data if the readLoop flag is
		 * false
		 * 
		 * @return the bytes read
		 * @see ConnectedThread#read()
		 */
		public byte[] read() {
			try {
				return mMessageBuffer.take();
			} catch (InterruptedException e) {
				Util.error("Message Read Interupted");
				return null;
			}
		}

		/**
		 * Write to the connected OutStream.
		 * 
		 * @param buffer
		 *            The bytes to write
		 */
		public void write(byte[] buffer) {
			try {
				mmOutStream.writeInt(buffer.length);
				mmOutStream.write(buffer);
				mmOutStream.flush();
			} catch (IOException e) {
				Util.error("Exception during write", e);
			}
		}

		public void run() {
			Util.disp("BEGIN mConnectedThread");

			int bytes;

			// Keep listening to the InputStream while connected
			while (true) {
				try {
					// Read from the InputStream
					bytes = mmInStream.readInt();
					// TODO: This is a little dangerous
					byte[] buffer = new byte[bytes];

					mmInStream.readFully(buffer, 0, bytes);

					try {
						mMessageBuffer.put(buffer);
					} catch (InterruptedException e) {
						Util.error("Message add interupted.");
						// TODO: possibly move this catch elsewhere
					}

				} catch (IOException e) {
					if (D)
						Util.debug("Device disconnected");
					connectionLost();
					break;
				}
			}
		}

		public void cancel() {
			try {
				mmInStream.close();
				mmOutStream.close();
				mmSocket.close();
			} catch (IOException e) {
				Util.error("close() of connect socket failed", e);
			}
		}
	}
}
