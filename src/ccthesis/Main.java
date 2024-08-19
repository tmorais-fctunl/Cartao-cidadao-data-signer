package ccthesis;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Scanner;

import pt.gov.cartaodecidadao.*;
import pteidlib.pteid;

public class Main {
	
	static {
		try {
			System.loadLibrary("pteidlibj"); //need to get this working using local jar... (had to change run args)
		} catch (UnsatisfiedLinkError e) {
	        System.err.println("Native code library failed to load. \n" + e);
	        System.exit(1);
	    }
	}
	
	private static String bytesToHex(byte[] hash) {
	    StringBuilder hexString = new StringBuilder(2 * hash.length);
	    for (int i = 0; i < hash.length; i++) {
	        String hex = Integer.toHexString(0xff & hash[i]);
	        if(hex.length() == 1) {
	            hexString.append('0');
	        }
	        hexString.append(hex);
	    }
	    return hexString.toString();
	}
	
	static PTEID_EIDCard getEIDCard(PTEID_EIDCard card, PTEID_ReaderContext context, PTEID_ReaderSet readerSet) {
		try {
			readerSet = PTEID_ReaderSet.instance();
			for( int i=0; i < readerSet.readerCount(); i++){
				context = readerSet.getReaderByNum(i);
				if (context.isCardPresent()){
					System.out.println("Card is present.");
					card = context.getEIDCard();
				}
			}
			return card;
		} catch (PTEID_Exception e) {
			System.err.println("Couldn't find card reader. \n" + e);
	        System.exit(1);
		}
		return null;
	}
	
	static PTEID_Card getCard(PTEID_Card card, PTEID_ReaderContext context, PTEID_ReaderSet readerSet) {
		try {
			readerSet = PTEID_ReaderSet.instance();
			for( int i=0; i < readerSet.readerCount(); i++){
				context = readerSet.getReaderByNum(i);
				if (context.isCardPresent()){
					System.out.println("Card is present.");
					card = context.getEIDCard();
				}
			}
			return card;
		} catch (PTEID_Exception e) {
			System.err.println("Couldn't find card reader. \n" + e);
	        System.exit(1);
		}
		return null;
	}
	

	static String[] getFullNameSplit(PTEID_EId eid) throws PTEID_Exception {
		String givenName = eid.getGivenName();
		String surname = eid.getSurname();
		String[] fullName = givenName.concat(" ").concat(surname).split(" ");
		return fullName;
		
	}
	
	static String createNewFile(String id, String path, String prefix) throws IOException {
		try {
			File dir = new File(path);
			File myObj = new File(dir, prefix.concat(id).concat(".txt"));
			if (myObj.createNewFile()) {
				//System.out.println("Input file created: " + myObj.getName());
				return myObj.getName();
			} 
			else {
				throw new IOException("File with same name already exists.");
			}
	    } 
		catch (IOException e) {
	      System.out.println("Couldn't proceed writing the file, an error occurred: ".concat(e.getMessage()));
	      throw e;
	    }
	  
	}
	
	static void writeToFile(String filename, String path, String[] data) throws IOException {
		try {
	      FileWriter myWriter = new FileWriter(path+filename);
	      for (int i = 0; i<data.length; i++)
	    	  myWriter.write(data[i]);
	      myWriter.close();
	      System.out.println("Successfully wrote to the file.");
	    } 
		catch (IOException e) {
	      System.out.println("An error occurred.");
	      throw e;
	    }
	}
	
	static void writeToSignedFile(String filename, String path, byte[] data) throws IOException {
		try (FileOutputStream outputStream = new FileOutputStream(path+filename)) {
		    outputStream.write(data);
		    System.out.println("Successfully wrote to the file.");
	    } 
		catch (IOException e) {
	      System.out.println("An error occurred.");
	      throw e;
	    }
	}
	
	static void verifySignedFile(String inputFile, String signedFile, PTEID_EIDCard card) throws CertificateException, PTEID_Exception, IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		byte[] inputBytes = Files.readAllBytes(Paths.get("inputFiles/".concat(inputFile)));
		byte[] signedBytes = Files.readAllBytes(Paths.get("signedFiles/".concat(signedFile)));
		validateSignature(card, inputBytes, signedBytes);
	}
	
	static void validateSignature(PTEID_EIDCard card, byte[] data, byte[] signature) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, PTEID_Exception {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		byte[] cardCertData = card.getSignature().getCertData().GetBytes();

		
		//byte[] cardCertData = card.getCert(PTEID_CertifType.PTEID_CERTIF_TYPE_SIGNATURE).getCertData().GetBytes();
		//byte[] cardCertData = card.getAuthentication().getCertData().GetBytes();
        
		InputStream in = new ByteArrayInputStream(cardCertData);
        // generate certificate (according to Java API)
        Certificate certif = certFactory.generateCertificate(in);
        // get certificate public key
        PublicKey publicKey = certif.getPublicKey();
        /*System.out.println("Public key Alg.: " + publicKey.getAlgorithm());
        System.out.println("Public key Format: " + publicKey.getFormat());
        System.out.println("Public key Length: " + publicKey.getEncoded().length);*/

        // verify signature
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(data);
      
        boolean signCorrect = publicSignature.verify(signature);
        
        System.out.println(signCorrect);
        
        System.out.println(signCorrect ? "Signature was verified successfuly" : "Signature does not verify");
		
	}
	
	static void signSha256v2(PTEID_EIDCard card, String inputFilename) throws NoSuchAlgorithmException, IOException, PTEID_Exception, InvalidKeyException, SignatureException, CertificateException {
		
		System.out.println("This is signing with the card");
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] byteArray = Files.readAllBytes(Paths.get("inputFiles/".concat(inputFilename)));
		byte[] hashedByteArray = sha256.digest(byteArray);
		//System.out.println("Hashed byte array has length " + hashedByteArray.length);
		System.out.println("Bytes provided in HEX: " + bytesToHex(byteArray));
		System.out.println("SHA-256 Hash bytes in HEX: " + bytesToHex(hashedByteArray));
		
		PTEID_ByteArray pteidByteArray = new PTEID_ByteArray(hashedByteArray, hashedByteArray.length);
		
		//Use PKCS:
		//PTEID_ByteArray signedByteArray = card.Sign(pteidByteArray, PTEID_RSAPaddingType.PADDING_TYPE_RSA_PKCS, true);
		
		//NO PKCS?
		PTEID_ByteArray signedByteArray = card.Sign(pteidByteArray, true);

		System.out.println("Here's your signed hash:");
		byte[] signedHash = signedByteArray.GetBytes();
		System.out.println("Signed bytes in HEX: " + bytesToHex(signedHash));
		
		String signedFilename = createNewFile(inputFilename.split(".txt")[0], "signedFiles/", "signed_");
		System.out.println(inputFilename.split(".txt")[0]);
		writeToSignedFile(signedFilename, "signedFiles/", signedHash);

		
		validateSignature(card, byteArray, signedHash);
		
		/*PTEID_Certificate certificate = card.getCert(PTEID_CertifType.PTEID_CERTIF_TYPE_SIGNATURE);
		System.out.println("Is this the public key?");
		certificate.getFormattedData(certificate.getCertData());
		System.out.println(certificate.getCertData().Size());*/
		
		
	}
	
	static void signDocument(PTEID_EIDCard EidCard) throws PTEID_Exception, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException {
		
		PTEID_EId eid = EidCard.getID();
		
		String fullname = eid.getGivenName().concat(" ").concat(eid.getSurname());
		String age = eid.getDateOfBirth();
		String gender = eid.getGender();
		
		String id = new Date().toInstant().toString();
		String inputFilename = createNewFile(id, "inputFiles/", "input");
		
		String[] information = new String[3];
		information[0] = fullname;
		information[1] = age;
		information[2] = gender;
		
		writeToFile(inputFilename, "inputFiles/", information);
		
		signSha256v2(EidCard, inputFilename);
		
	
	}
	
	public static void main(String[] args) throws PTEID_Exception, InvalidKeyException, SignatureException, CertificateException {
		
		Scanner keyboard = new Scanner(System.in);
		try {
			boolean exit = false;
			
			PTEID_ReaderSet.initSDK();
			PTEID_Config.SetTestMode(false);
			PTEID_ReaderSet readerSet = PTEID_ReaderSet.instance();
			PTEID_ReaderContext readerContext = readerSet.getReader();
			pteidlibJava_Wrapper.setCompatReaderContext(readerContext);
			
			while(!exit) {
				PTEID_EIDCard card = getEIDCard(null, readerContext, readerSet);
				String input = "";
				if (card==null) {
					System.out.println("No card was presented. Insert a card and Press Y and Enter to try again. If not, press N and Enter to exit.");
					input = keyboard.nextLine().toUpperCase().trim();
					switch (input) {
						case "Y":
							continue;
							//break;
						case "N":
							exit = true;
							break;
						default:
							System.out.println("Invalid command.");
							break;
					}
				}
				else {
					PTEID_EId eid = card.getID();
					String[] fullNameSplit = getFullNameSplit(eid);
					int fullNameLength = fullNameSplit.length;
					String username = fullNameLength>1 ? fullNameSplit[0].concat(" ").concat(fullNameSplit[fullNameLength-1]) : fullNameSplit[0];
					System.out.printf("Card was successfully read. Welcome %s\n", username);
					System.out.println("Type \"help\" followed by an enter to view possible commands");
					//boolean logout = false;
					
					while(!exit) {
						input = keyboard.nextLine().toUpperCase().trim();
						
						switch(input) {
							case "EXIT":
								System.out.printf("Goodbye %s!", username);
								exit = true;
								break;
							case "SIGN":
								System.out.println("We'll be signing your given name, birth date, and gender.\nPlease hold while we're signing your information...");
								signDocument(card);
								System.out.println("The signature has been completed. Check the most recent output file in the signedFiles folder.");
								break;
							case "HELP":
								System.out.println("Valid commands are:");
								System.out.println("HELP - Displays the available commands in the current version.");
								System.out.println("EXIT - Ends the session and exits the program.");
								System.out.println("SIGN - Saves a SHA256 signature of your given name, birth date and gender into an output file in the signedFiles folder.");
								System.out.println("VERIFY - Verifies if a signature file in signedFiles folder is valid according to an input file in inputFiles folder, according to the card holder's public key");
								break;
							case "VERIFY":
								System.out.println("Input the inputFile's name:");
								String inputFile = keyboard.nextLine();
								System.out.println("Input the signedFile's name:");
								String signedFile = keyboard.nextLine();
								System.out.println("Checking if signed file is a valid signature of input file:");
								verifySignedFile(inputFile, signedFile, card);
								break;
							default:
								System.out.println("Invalid command.");
								break;
						}
						
					}
					PTEID_ReaderSet.releaseSDK();
					keyboard.close();
					System.exit(0);
					
				}		
			}
			
		} catch (pt.gov.cartaodecidadao.PTEID_Exception | NoSuchAlgorithmException | IOException e) {
			if (e instanceof pt.gov.cartaodecidadao.PTEID_Exception)
				System.err.println("Error: \n" + ((PTEID_Exception) e).GetError() + ": " + ((PTEID_Exception) e).GetMessage());
			else {
				System.err.println("Error: \n" + e.getMessage());
			}
		} finally {
			PTEID_ReaderSet.releaseSDK();
			keyboard.close();
			System.out.println("Exiting program...");
		}
			
	}
}
