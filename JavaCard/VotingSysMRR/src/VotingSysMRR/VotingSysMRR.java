package VotingSysMRR;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class VotingSysMRR extends Applet {
	
	// Voter card CLA
	final static byte VoterCard_CLA 	= (byte) 0xB0;
	
	// Voter card INS
	final static byte REG_FIRST_NAME 	= (byte) 0x01;
	final static byte REG_LAST_NAME 	= (byte) 0x02;
	final static byte REG_SEX 			= (byte) 0x03;
	final static byte REG_BIRTH_DATE 	= (byte) 0x04;
	
	final static byte GET_FIRST_NAME 	= (byte) 0x05;
	final static byte GET_LAST_NAME 	= (byte) 0x06;
	final static byte GET_BIRTH_DATE 	= (byte) 0x07;
	final static byte GET_SEX_VALUE 	= (byte) 0x08;
	
	final static byte UPDATE_PIN 		= (byte) 0x09;
	final static byte VERIFY_PIN 		= (byte) 0x0A;
	final static byte RESET_PIN 		= (byte) 0x0B;
	
	final static byte INITIALIZE		= (byte) 0x0C;
	final static byte IS_INITIALIZED	= (byte) 0x0D;
	
	final static byte GET_CARD_ID 		= (byte) 0x0E;
	final static byte GET_PIN_ATTEMPTS	= (byte) 0x0F;
	
	final static byte GEN_HASH			= (byte) 0xA0;
	
	final static byte GEN_RSA_KEYPAIR	= (byte) 0x30;
	final static byte GET_RSA_PUBKEY	= (byte) 0x31;
	final static byte GET_RSA_PRIKEY	= (byte) 0x32;
	final static byte SET_RSA_PUBKEY	= (byte) 0x33;
	final static byte SET_RSA_PRIKEY	= (byte) 0x34;
	final static byte RSA_SIGN			= (byte) 0x35;
	final static byte RSA_VERIFY		= (byte) 0x36;
	final static byte DO_RSA_CIPHER		= (byte) 0x37;
	// other INS...
	
	// variables
	private byte[] firstName 			= new byte[30];
	private byte[] lastName 			= new byte[30];
	private byte[] birthDate 			= new byte[4];
	private byte sex;
	private byte[] tmpPIN 				= new byte[5];
	private byte initialized			= (byte) 0x00;
	
	private RandomData rng 				= RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	private byte[] rndBuffer			= new byte[2];
	
	
	private byte[] cardID 				= new byte[8];
	//private byte[] address;
	
	final static byte PIN_TRY_LIMIT 	= (byte) 0x0A;
	final static byte PIN_SIZE 			= (byte) 0x05;
	
	// Hashes
	private InitializedMessageDigest sha1;
    private InitializedMessageDigest sha256;
    private InitializedMessageDigest sha512;
    
    // RSA
    private byte[] tempBuffer;
    
    private static final byte ID_N   = 0;
	private static final byte ID_D   = 1;
	private static final byte ID_P   = 2;
	private static final byte ID_Q   = 3;
	private static final byte ID_PQ  = 4;
	private static final byte ID_DP1 = 5;
	private static final byte ID_DQ1 = 6;
	
	private byte[] rsaPubKey;
	private short rsaPubKeyLen;
	private byte[] rsaPriKey;
	private short rsaPriKeyLen;
	private boolean isRSAPriKeyCRT;
	private Cipher rsaCipher;    
	private Signature rsaSignature;
    
    // flags
	private byte[] flags;
    private static final short OFF_INS    = (short)0;
    private static final short OFF_P1     = (short)1;
    private static final short OFF_P2     = (short)2;
    private static final short OFF_LEN    = (short)3;
    private static final short FLAGS_SIZE = (short)5;
	
	// signal that the PIN verification failed
	final static short SW_VERIFICATION_FAILED 		= 0x6300;
	// signal the the PIN validation is required
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	final static short SW_ALREADY_INITIALIZED		= 0x6301;
	
	private static final short SW_REFERENCE_DATA_NOT_FOUND = (short)0x6A88;
	
	// pin
	OwnerPIN pin;
	
	private VotingSysMRR(byte[] bArray, short bOffset, byte bLength) {
		
		// RSA
		//Create a transient byte array to store the temporary data
		tempBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
		flags = JCSystem.makeTransientByteArray(FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);

		rsaPubKey = new byte[(short)   (256 + 32)];
		rsaPriKey = new byte[(short)(128 * 5)];
		rsaPubKeyLen = 0;
		rsaPriKeyLen = 0;
		isRSAPriKeyCRT = false;
		rsaSignature = null;
		//Create a RSA(not pad) object instance
		rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		
		// Hash
		flags = JCSystem.makeTransientByteArray(FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);
		//Creates a InitializedMessageDigest object instance of the ALG_SHA algorithm.
		sha1 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA, false);
		//Creates a InitializedMessageDigest object instance of the ALG_SHA_256 algorithm.
		sha256 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
		//Creates a InitializedMessageDigest object instance of the ALG_SHA_512 algorithm.
		sha512 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_512, false);
		JCSystem.requestObjectDeletion();
		
		// PIN
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		byte iLen = bArray[bOffset];
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset];
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset];
        pin.update(bArray, (short) (bOffset + 1), aLen);
        
        register();
	}

    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
    	// create a VoterCard applet instance
        new VotingSysMRR(bArray, bOffset, bLength);
    }
    
    @Override
    public boolean select() {
    	
    	if (pin.getTriesRemaining() == 0) {
    		return false;
    	}
    	return true;
    }
    
    @Override
    public void deselect() {
    	pin.reset();
    }

    /**
     * Only this class's install method should create the applet object.
     /
    protected VoterCard() {
        register();
    }*/

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
        //Insert your code here
    	byte[] buffer = apdu.getBuffer();
    	/*if (apdu.isISOInterindustryCLA()) {
    		if (buffer[ISO7816.OFFSET_INS] == (0xA4)) {
    			return;
    		}
    		ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    	}*/
    	
    	if (this.selectingApplet()) return;
    	
    	if (buffer[ISO7816.OFFSET_CLA] != VoterCard_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    	
    	switch (buffer[ISO7816.OFFSET_INS]) {
    	case REG_FIRST_NAME:
    		setFirstName(apdu);
    		break;
    	case REG_LAST_NAME:
    		setLastName(apdu);
    		break;
    	case REG_SEX:
    		setSex(apdu);
    		break;
    	case REG_BIRTH_DATE:
    		setBirthDate(apdu);
    		break;
    	case GET_FIRST_NAME:
    		getFirstName(apdu);
    		break;
    	case GET_LAST_NAME:
    		getLastName(apdu);
    		break;
    	case GET_BIRTH_DATE:
    		getBirthDate(apdu);
    		break;
    	case GET_SEX_VALUE:
    		getSexValue(apdu);
    		break;
    	case UPDATE_PIN:
    		updatePIN(apdu);
    		break;
    	case VERIFY_PIN:
    		verifyPIN(apdu);
    		break;
    	case RESET_PIN:
    		resetPIN(apdu);
    		break;
    	case INITIALIZE:
    		initialize(apdu);
    		break;
    	case IS_INITIALIZED:
    		isInitialized(apdu);
    		break;
    	case GET_CARD_ID:
    		getCardID(apdu);
    		break;
    	case GET_PIN_ATTEMPTS:
    		getPINAttempts(apdu);
    		break;
    	case GEN_HASH:
    		generateHash(apdu);
    		break;
    	case GEN_RSA_KEYPAIR:
		   genRsaKeyPair(apdu);
			break;
		case GET_RSA_PUBKEY:
			getRsaPubKey(apdu);
			break;
		case GET_RSA_PRIKEY:
		   getRsaPriKey(apdu);
			break;
		case SET_RSA_PUBKEY:
			setRsaPubKey(apdu);
			break;
		case SET_RSA_PRIKEY:
			setRsaPriKey(apdu);
			break;
		case RSA_SIGN:
			rsaSign(apdu);
			break;
		case RSA_VERIFY:
			rsaVerify(apdu);
			break;
		case DO_RSA_CIPHER:   
		   doRSACipher(apdu);
		   break;
    	default:
    		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    	}
    }
    
    private void setFirstName(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	byte numBytes = (buffer[ISO7816.OFFSET_LC]);
    	for (short i=0; i<(short)numBytes; i++) {
    		firstName[i] = buffer[ISO7816.OFFSET_CDATA+(byte)i];
    	}
    }
    
    private void setLastName(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	byte numBytes = (buffer[ISO7816.OFFSET_LC]);
    	for (short i=0; i<(short)numBytes; i++) {
    		lastName[i] = buffer[ISO7816.OFFSET_CDATA+(byte)i];
    	}
    }
    
    private void setSex(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	apdu.setIncomingAndReceive();
    	sex = buffer[ISO7816.OFFSET_CDATA];
    }
    
    private void setBirthDate(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	byte numBytes = (buffer[ISO7816.OFFSET_LC]);
    	for (short i=0; i<(short)numBytes; i++) {
    		birthDate[i] = buffer[ISO7816.OFFSET_CDATA+(byte)i];
    	}
    }
    
    private void getFirstName(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	Util.arrayCopyNonAtomic(firstName, (short) 0, buffer, (short) 0, (short) firstName.length);
		apdu.setOutgoingAndSend((short) 0, (short) firstName.length);
    }
    
    private void getLastName(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	Util.arrayCopyNonAtomic(lastName, (short) 0, buffer, (short) 0, (short) lastName.length);
		apdu.setOutgoingAndSend((short) 0, (short) lastName.length);
    }
    
    private void getBirthDate(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	Util.arrayCopyNonAtomic(birthDate, (short) 0, buffer, (short) 0, (short) birthDate.length);
		apdu.setOutgoingAndSend((short) 0, (short) birthDate.length);
    }
    
    private void getSexValue(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	buffer[0] = sex;
    	apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
    
    private void updatePIN(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	byte numBytes = (buffer[ISO7816.OFFSET_LC]);
    	for (short i=0; i<(short)numBytes; i++) {
    		tmpPIN[i] = buffer[ISO7816.OFFSET_CDATA+(byte)i];
    	}
    	pin.update(tmpPIN, (short) 0, (byte) tmpPIN.length);
    }
    
    private void verifyPIN(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	byte byteRead = (byte) (apdu.setIncomingAndReceive());
    	if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
    		ISOException.throwIt(SW_VERIFICATION_FAILED);
    	}
    }
    
    private void resetPIN(APDU apdu) {
    	pin.resetAndUnblock();
    }
    
    private void initialize(APDU apdu) {
    	/*do {
    		rng.generateData(rndBuffer, (short) 0, (short) 2);
    	} while ((rndBuffer[0] > (byte) 0x63) || (rndBuffer[1] > (byte) 0x63)); // 0x63 = 99*/
    	rng.generateData(rndBuffer, (short) 0, (short) 2);
    	cardID[0] = lastName[0];
    	cardID[1] = firstName[0];
    	cardID[2] = birthDate[2];
    	cardID[3] = birthDate[3];
    	cardID[4] = birthDate[1];
    	cardID[5] = birthDate[0];
    	cardID[6] = rndBuffer[0];
    	cardID[7] = rndBuffer[1];
    	initialized = (byte) 0x01;
    }
    
    private void isInitialized(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	buffer[0] = initialized;
    	apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
    
    private void getCardID(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	Util.arrayCopyNonAtomic(cardID, (short) 0, buffer, (short) 0, (short) cardID.length);
		apdu.setOutgoingAndSend((short) 0, (short) cardID.length);
    }
    
    private void getPINAttempts(APDU apdu){
	    byte[] buffer = apdu.getBuffer();
	    buffer[0] = (byte) pin.getTriesRemaining();
	    apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
    
    //Generate Hash
    private void generateHash(APDU apdu)
    {
    	short len = apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        boolean hasMoreCmd = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;
        InitializedMessageDigest hash = null;
        short resultLen = 0;
        short offset = ISO7816.OFFSET_CDATA;
        switch (buffer[ISO7816.OFFSET_P1] & 0x7f)
        {
        case 0:
            hash = sha1;
            resultLen = MessageDigest.LENGTH_SHA;
            break;
        case 1:
            hash = sha256;
            resultLen = MessageDigest.LENGTH_SHA_256;
            break;
        case 2:
            hash = sha512;
            resultLen = MessageDigest.LENGTH_SHA_512;
            if (hash == null)
            {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            break;
        }
 
        if (buffer[ISO7816.OFFSET_P2] == 0) //first block
        {
            //Reset the MessageDigest object to the initial state.
            hash.reset();
        }
 
        if (hasMoreCmd)
        {
            //Accumulate a hash of the input data.
            hash.update(buffer, offset, len);
        }
        else
        {
            //Generate a hash of all the input data.
            short ret = hash.doFinal(buffer, offset, len, buffer, (short)0);
            Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
            apdu.setOutgoingAndSend((short)0, ret);
        }
    }
    
    // RSA
    
    //RSA algorithm encrypt and decrypt
	private void doRSACipher(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		byte p1Tmp = buffer[ISO7816.OFFSET_P1];
		boolean hasMoreCmd = (p1Tmp & 0x80) != 0;
		boolean isEncrypt = (p1Tmp & 0x01) != 1;
		short keyLen = (p1Tmp & 0x08) == (byte)0x00 ? KeyBuilder.LENGTH_RSA_1024 : KeyBuilder.LENGTH_RSA_2048;
		short offset = (p1Tmp & 0x08) == (byte)0x00 ? (short)128 : (short)256;
	   
		if (len <= 0)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		//RSA encrypt, Public Key will be used
		if (isEncrypt)
	  {
		 //Create uninitialized public key for signature and cipher algorithms.
		 RSAPublicKey pubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keyLen, false);
		 pubKey.setModulus(rsaPubKey, (short)0, offset);
		 pubKey.setExponent(rsaPubKey, offset, (short)3);
		 if (buffer[ISO7816.OFFSET_P2] == 0x00)
		 {
			//In multiple-part encryption/decryption operations, only the fist APDU command will be used.
			rsaCipher.init(pubKey, Cipher.MODE_ENCRYPT); 
		 }
		 
		 if (hasMoreCmd)
		 {
			//This method is intended for multiple-part encryption/decryption operations.
			rsaCipher.update(buffer, ISO7816.OFFSET_CDATA, len, tempBuffer, (short)0);
		 }
		 else
		 {
			//Generates encrypted output from all input data.
			short outlen = rsaCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
			apdu.setOutgoingAndSend((short)0, outlen);   
		 }
	  }
	  else//RSA decrypt, Private Key will be used
	  {
		 if (!isRSAPriKeyCRT)
			{
			   //RSA Alogrithm, create uninitialized private key for decypt
			   RSAPrivateKey priKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLen, false);
			   //Set the modulus value of the key.
			priKey.setModulus(rsaPriKey, (short)0, offset);
			//Sets the private exponent value of the key
			priKey.setExponent(rsaPriKey, offset, offset);
			if (buffer[ISO7816.OFFSET_P2] == 0x00)
			{
			   //In multiple-part encryption/decryption operations, only the fist APDU command will be used.
			   rsaCipher.init(priKey, Cipher.MODE_DECRYPT);
			}
			if (hasMoreCmd)
			{
			   //This method is intended for multiple-part encryption/decryption operations.
			   rsaCipher.update(buffer, ISO7816.OFFSET_CDATA, len, tempBuffer, (short)0);
			}
			else
			{
			   short outlen = rsaCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
			   apdu.setOutgoingAndSend((short)0, outlen);   
			}
			}
			else 
			{
			   //RSA CRT Algorithm, need to create uninitialized private key and set the value of some parameters, such as P Q PQ DP DQ.
			   RSAPrivateCrtKey priCrtKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keyLen, false);
				priCrtKey.setP(rsaPriKey, (short)0, (short)(offset / 2));
				priCrtKey.setQ(rsaPriKey, (short)(offset / 2), (short)(offset / 2));
				priCrtKey.setPQ(rsaPriKey, (short)offset, (short)(offset / 2));
				priCrtKey.setDP1(rsaPriKey, (short)(offset + offset / 2), (short)(offset / 2));
				priCrtKey.setDQ1(rsaPriKey, (short)(offset * 2), (short)(offset / 2));
				
				if (buffer[ISO7816.OFFSET_P2] == 0x00)
			{
			   //Initializes the Cipher object with the appropriate Key. 
			   //In multiple-part encryption/decryption operations, only the fist APDU command will be used.
			   rsaCipher.init(priCrtKey, Cipher.MODE_DECRYPT);
			}
			if (hasMoreCmd)
			{
			   //This method is intended for multiple-part encryption/decryption operations.
			   rsaCipher.update(buffer, ISO7816.OFFSET_CDATA, len, tempBuffer, (short)0);
			}
			else
			{
			   //Generates decrypted output from all input data.
			   short outlen = rsaCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
			   apdu.setOutgoingAndSend((short)0, outlen);   
			}
			}
	  }        
	}
	
    //Get the value of RSA Public Key from the global variable 'rsaPubKey' 
	private void getRsaPubKey(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if (rsaPubKeyLen == 0)
		{
			ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
		}

		short modLen = rsaPubKeyLen <= (128 + 32) ? (short)128 : (short)256;
		switch (buffer[ISO7816.OFFSET_P1])
		{
		case 0:
			Util.arrayCopyNonAtomic(rsaPubKey,(short)0,buffer,(short)0,modLen);
			apdu.setOutgoingAndSend((short)0,modLen);
			break;
		case 1:
			//get public key E
			short eLen = (short)(rsaPubKeyLen - modLen);
			Util.arrayCopyNonAtomic(rsaPubKey,modLen,buffer,(short)0,eLen);
			apdu.setOutgoingAndSend((short)0,eLen);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}

	}
   //According to the different ID, returns the value/length of RSA Private component
	private short getRsaPriKeyComponent(byte id, byte[] outBuff, short outOff)
	{
		if (rsaPriKeyLen == 0)
		{
			return (short)0;
		}
		short modLen;
		if (isRSAPriKeyCRT)
		{
			if (rsaPriKeyLen == 64 * 5)
			{
				modLen = (short)128;
			}
			else
			{
				modLen = (short)256;
			}
		}
		else
		{
			if (rsaPriKeyLen == 128 * 2)
			{
				modLen = (short)128;
			}
			else
			{
				modLen = (short)256;
			}
		}
		short readOff;
		short readLen;

		switch (id)
		{
		case ID_N:
			//RSA private key N
			if (isRSAPriKeyCRT)
			{
				return (short)0;
			}
			readOff = (short)0;
			readLen = modLen;
			break;
		case ID_D:
			if (isRSAPriKeyCRT)
			{
				return (short)0;
			}
			//RSA private key D
			readOff = modLen;
			readLen = modLen;
			break;
		case ID_P:
			if (!isRSAPriKeyCRT)
			{
				return (short)0;
			}
			readOff = (short)0;
			readLen = (short)(modLen / 2);
			break;
		case ID_Q:
			if (!isRSAPriKeyCRT)
			{
				return (short)0;
			}
			readOff = (short)(modLen / 2);
			readLen = (short)(modLen / 2);
			break;
		case ID_PQ:
			if (!isRSAPriKeyCRT)
			{
				return (short)0;
			}
			readOff = (short)(modLen);
			readLen = (short)(modLen / 2);
			break;
		case ID_DP1:
			if (!isRSAPriKeyCRT)
			{
				return (short)0;
			}
			readOff = (short)(modLen / 2 * 3);
			readLen = (short)(modLen / 2);
			break;
		case ID_DQ1:
			if (!isRSAPriKeyCRT)
			{
				return (short)0;
			}
			readOff = (short)(modLen * 2);
			readLen = (short)(modLen / 2);
			break;
		default:
			return 0;
		}
		Util.arrayCopyNonAtomic(rsaPriKey, readOff, outBuff, outOff, readLen);
		return readLen;
	}

   //Get the value of RSA Private Key
	private void getRsaPriKey(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if ((buffer[ISO7816.OFFSET_P1] & 0xff) > 6)
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		short ret = getRsaPriKeyComponent(buffer[ISO7816.OFFSET_P1], buffer, (short)0);
		if (ret == 0)
		{
			ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
		}
		apdu.setOutgoingAndSend((short)0, ret);
	}

   //Set the value of RSA public key
	private void setRsaPubKey(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if (buffer[ISO7816.OFFSET_P2] == 0) // first block
		{
			rsaPubKeyLen = (short)0;
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_INS, flags, OFF_INS, (short)3);
			Util.setShort(flags, OFF_LEN, (short)0);
		}
		else
		{
			if (flags[OFF_INS] != buffer[ISO7816.OFFSET_INS]
					|| (flags[OFF_P1] & 0x7f) != (buffer[ISO7816.OFFSET_P1] & 0x7f)
					|| (short)(flags[OFF_P2] & 0xff) != (short)((buffer[ISO7816.OFFSET_P2] & 0xff) - 1))
			{
				Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}

			flags[OFF_P2] ++;
		}
		short loadedLen = Util.getShort(flags, OFF_LEN);
		if (loadedLen + len > rsaPubKey.length)
		{
			Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	  //Copy the value of RSA public key  to the global variable 'rsaPubKey'. 
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, rsaPubKey, loadedLen, len);
		loadedLen += len;

		if ((buffer[ISO7816.OFFSET_P1] & 0x80) == 0) //last block
		{
			Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
			short modLen = (buffer[ISO7816.OFFSET_P1] & 0x01) == 0 ? (short)128 : (short)256;
			if (loadedLen < modLen + 3 || loadedLen > modLen + 32)
			{
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}

			rsaPubKeyLen = loadedLen;
		}
		else
		{
			Util.setShort(flags, OFF_LEN, loadedLen);
		}

	}

   //Set the value of RSA private key
	private void setRsaPriKey(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if (buffer[ISO7816.OFFSET_P2] == 0) // first block
		{
			rsaPriKeyLen = (short)0;
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_INS, flags, OFF_INS, (short)3);
			Util.setShort(flags, OFF_LEN, (short)0);
		}
		else
		{
			if (flags[OFF_INS] != buffer[ISO7816.OFFSET_INS]
					|| (flags[OFF_P1] & 0x7f) != (buffer[ISO7816.OFFSET_P1] & 0x7f)
					|| (short)(flags[OFF_P2] & 0xff) != (short)((buffer[ISO7816.OFFSET_P2] & 0xff) - 1))
			{
				Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}

			flags[OFF_P2] ++;
		}
		short loadedLen = Util.getShort(flags, OFF_LEN);
		if (loadedLen + len > rsaPriKey.length)
		{
			Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	  //Copy the value of RSA private key  to the global variable 'rsaPriKey'.
	  Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, rsaPriKey, loadedLen, len);
		loadedLen += len;

		if ((buffer[ISO7816.OFFSET_P1] & 0x80) == 0) //last block
		{
			Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
			short modLen = (buffer[ISO7816.OFFSET_P1] & 0x01) == 0 ? (short)128 : (short)256;
			boolean isCRT = (buffer[ISO7816.OFFSET_P1] & 0x40) != 0;
			if ((isCRT && (loadedLen != modLen / 2 * 5)) || (!isCRT && (loadedLen != modLen * 2)))
			{
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}

			isRSAPriKeyCRT = isCRT;
			rsaPriKeyLen = loadedLen;
		}
		else
		{
			Util.setShort(flags, OFF_LEN, loadedLen);
		}
	}
	//
   private void genRsaKeyPair(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		short keyLen = buffer[ISO7816.OFFSET_P1] == 0 ? (short)1024 : (short)2048;
		byte alg = buffer[ISO7816.OFFSET_P2] == 0 ? KeyPair.ALG_RSA : KeyPair.ALG_RSA_CRT;
		KeyPair keyPair = new KeyPair(alg, keyLen);
		if (len > 32)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		if (len > 0)
		{
			((RSAPublicKey)keyPair.getPublic()).setExponent(buffer, ISO7816.OFFSET_CDATA, len);
		}
		//(Re)Initializes the key objects encapsulated in this KeyPair instance with new key values.
		keyPair.genKeyPair();
		JCSystem.beginTransaction();
		rsaPubKeyLen = 0;
		rsaPriKeyLen = 0;
		JCSystem.commitTransaction();
		//Get a reference to the public key component of this 'keyPair' object.
		RSAPublicKey pubKey = (RSAPublicKey)keyPair.getPublic();
		short pubKeyLen = 0;
		//Store the RSA public key value in the global variable 'rsaPubKey', the public key contains modulo N and Exponent E
		pubKeyLen += pubKey.getModulus(rsaPubKey, pubKeyLen);
		pubKeyLen += pubKey.getExponent(rsaPubKey, pubKeyLen);

		short priKeyLen = 0;
		if (alg == KeyPair.ALG_RSA)
		{
		   isRSAPriKeyCRT = false;
		   //Returns a reference to the private key component of this KeyPair object.
			RSAPrivateKey priKey = (RSAPrivateKey)keyPair.getPrivate();
			//RSA Algorithm,  the Private Key contains N and D, and store these parameters value in global variable 'rsaPriKey'.
			priKeyLen += priKey.getModulus(rsaPriKey, priKeyLen);
			priKeyLen += priKey.getExponent(rsaPriKey, priKeyLen);
		}
		else //RSA CRT
		{
		   isRSAPriKeyCRT =  true;
		   //The RSAPrivateCrtKey interface is used to sign data using the RSA algorithm in its Chinese Remainder Theorem form.
			RSAPrivateCrtKey priKey = (RSAPrivateCrtKey)keyPair.getPrivate();
			//RSA CRT Algorithm,  the Private Key contains P Q PQ DP and DQ, and store these parameters value in global variable 'rsaPriKey'.
			priKeyLen += priKey.getP(rsaPriKey, priKeyLen);
			priKeyLen += priKey.getQ(rsaPriKey, priKeyLen);
			priKeyLen += priKey.getPQ(rsaPriKey, priKeyLen);
			priKeyLen += priKey.getDP1(rsaPriKey, priKeyLen);
			priKeyLen += priKey.getDQ1(rsaPriKey, priKeyLen);
		}

		JCSystem.beginTransaction();
		rsaPubKeyLen = pubKeyLen;
		rsaPriKeyLen = priKeyLen;
		JCSystem.commitTransaction();

		JCSystem.requestObjectDeletion();
	}
   //RSA Signature
	private void rsaSign(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if (rsaPriKeyLen == 0)
		{
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		boolean hasMoreCmd = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;
		short resultLen = 0;
		if (buffer[ISO7816.OFFSET_P2] == 0) //first block
		{
			Key key;
			if (!isRSAPriKeyCRT)
			{
				short ret;
				//Creates uninitialized private keys for signature algorithms.
				key = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)(rsaPriKeyLen / 2 * 8), false);
				ret = getRsaPriKeyComponent(ID_N, tempBuffer, (short)0);
				((RSAPrivateKey)key).setModulus(tempBuffer, (short)0, ret);
				ret = getRsaPriKeyComponent(ID_D, tempBuffer, (short)0);
				((RSAPrivateKey)key).setExponent(tempBuffer, (short)0, ret);
			}
			else
			{
				short ret;
				//Creates uninitialized private keys for signature algorithms.
				key = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, (short)(rsaPriKeyLen / 5 * 16), false);
				ret = getRsaPriKeyComponent(ID_P, tempBuffer, (short)0);
				((RSAPrivateCrtKey)key).setP(tempBuffer, (short)0, ret);
				ret = getRsaPriKeyComponent(ID_Q, tempBuffer, (short)0);
				((RSAPrivateCrtKey)key).setQ(tempBuffer, (short)0, ret);
				ret = getRsaPriKeyComponent(ID_DP1, tempBuffer, (short)0);
				((RSAPrivateCrtKey)key).setDP1(tempBuffer, (short)0, ret);
				ret = getRsaPriKeyComponent(ID_DQ1, tempBuffer, (short)0);
				((RSAPrivateCrtKey)key).setDQ1(tempBuffer, (short)0, ret);
				ret = getRsaPriKeyComponent(ID_PQ, tempBuffer, (short)0);
				((RSAPrivateCrtKey)key).setPQ(tempBuffer, (short)0, ret);
			}
		 // Creates a Signature object instance of the ALG_RSA_SHA_256_PKCS1 algorithm.
			rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);
			JCSystem.requestObjectDeletion();
		 //Initializ the Signature object.
			rsaSignature.init(key, Signature.MODE_SIGN);

			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_INS, flags, OFF_INS, (short)3);
			JCSystem.requestObjectDeletion();
		}
		else
		{
			if (flags[OFF_INS] != buffer[ISO7816.OFFSET_INS]
					|| (flags[OFF_P1] & 0x7f) != (buffer[ISO7816.OFFSET_P1] & 0x7f)
					|| (short)(flags[OFF_P2] & 0xff) != (short)((buffer[ISO7816.OFFSET_P2] & 0xff) - 1))
			{
				Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}

			flags[OFF_P2] ++;
		}

		if (hasMoreCmd)
		{
		   // Accumulates a signature of the input data. 
			rsaSignature.update(buffer, ISO7816.OFFSET_CDATA, len);
		}
		else
		{
		   //Generates the signature of all input data.
			short ret = rsaSignature.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
			Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
			apdu.setOutgoingAndSend((short)0, ret);
		}
	}
	//RSA Signature and Verify
	private void rsaVerify(APDU apdu)
	{
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if (rsaPubKeyLen == 0)
		{
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		boolean hasMoreCmd = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;
		short resultLen = 0;
		short offset = ISO7816.OFFSET_CDATA;
		short modLen = rsaPubKeyLen > 256 ? (short)256 : (short)128;
		if (buffer[ISO7816.OFFSET_P2] == 0) //first block
		{
			Key key;
			// Create uninitialized public keys for signature  algorithms.
			key = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)(modLen * 8), false);
			//Sets the modulus value of the key. 
			((RSAPublicKey)key).setModulus(rsaPubKey, (short)0, modLen);
			//Sets the public exponent value of the key.
			((RSAPublicKey)key).setExponent(rsaPubKey, modLen, (short)(rsaPubKeyLen - modLen));

		 //Create a ALG_RSA_SHA_256_PKCS1 object instance.
			rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);
			JCSystem.requestObjectDeletion();
			//Initializes the Signature object with the appropriate Key. 
			rsaSignature.init(key, Signature.MODE_VERIFY);
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_INS, flags, OFF_INS, (short)3);
			Util.setShort(flags, OFF_LEN, (short)0);
			JCSystem.requestObjectDeletion();
		}
		else
		{
			if (flags[OFF_INS] != buffer[ISO7816.OFFSET_INS]
					|| (flags[OFF_P1] & 0x7f) != (buffer[ISO7816.OFFSET_P1] & 0x7f)
					|| (short)(flags[OFF_P2] & 0xff) != (short)((buffer[ISO7816.OFFSET_P2] & 0xff) - 1))
			{
				Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}

			flags[OFF_P2] ++;
		}

		short sigLen = Util.getShort(flags, OFF_LEN);
		if (sigLen < modLen)
		{
			short readLen = (short)(modLen - sigLen);
			if (readLen > len)
			{
				readLen = len;
			}
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, sigLen, readLen);
			sigLen += readLen;
			len -= readLen;
			Util.setShort(flags, OFF_LEN, sigLen);
			offset += readLen;
		}
		if (hasMoreCmd)
		{
			if (len > 0)
			{
			   //Accumulates a signature of the input data. 
				rsaSignature.update(buffer, offset, len);
			}
		}
		else
		{
			if (sigLen != modLen)
			{
				Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			//Verify the signature of all/last input data against the passed in signature.
			boolean ret = rsaSignature.verify(buffer, offset, len, tempBuffer, (short)0, sigLen);
			Util.arrayFillNonAtomic(flags, (short)0, (short)flags.length, (byte)0);
			buffer[(short)0] = ret ? (byte)1 : (byte)0;
			apdu.setOutgoingAndSend((short)0, (short)1);
		}
	}
}