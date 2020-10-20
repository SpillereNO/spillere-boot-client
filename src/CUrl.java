import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.net.Proxy;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

@SuppressWarnings({"rawtypes", "unchecked", "serial"})
public final class CUrl {
	private static final String VERSION = "1.2.2";
	private static final String DEFAULT_USER_AGENT = "Java-CURL version " + VERSION + " by Rocks Wang(https://github.com/rockswang)";
	private static final Pattern ptnOptionName = Pattern.compile("-{1,2}[a-zA-Z][a-zA-Z0-9\\-.]*");
	private static final CookieStore cookieStore = new CookieStore();
	private static HostnameVerifier insecureVerifier = null;
	private static SSLSocketFactory insecureFactory = null;

	static {
		try {
			// Try to enable the setting to restricted headers like "Origin", this is expected to be executed before HttpURLConnection class-loading
			System.setProperty("sun.net.http.allowRestrictedHeaders", "true");

			// Modify the system-wide Cookie manager to ThreadLocal-based instance
			CookieManager.setDefault(new CookieManager(cookieStore, CookiePolicy.ACCEPT_ALL));

			// For insecure HTTPS
			insecureVerifier = new HostnameVerifier() {
				public boolean verify(String hostname, SSLSession session) { return true; }
			};
			insecureFactory = getSocketFactory(null, null);
		} catch (Exception ignored) {}
	}

	private static final Map<String, Integer> optMap = Util.mapPut(new LinkedHashMap<String, Integer>(),
			"-E", 32,
			"--cert", 32, 					// <certificate[:password]> Client certificate file and password
			"--compressed", 1, 				// Request compressed response (using deflate or gzip)
			"--connect-timeout", 2, 		// SECONDS  Maximum time allowed for connection
			"-b", 3, 
			"--cookie", 3, 					// STRING/FILE  Read cookies from STRING/FILE (H)
			"-c", 4,
			"--cookie-jar", 4, 				// FILE  Write cookies to FILE after operation (H)
			"-d", 5,
			"--data", 5, 					// DATA	 HTTP POST data (H)
			"--data-ascii", 5, 				// DATA	 HTTP POST ASCII data (H)
			"--data-raw", 51, 				// DATA	 HTTP POST raw data (H)
			"--data-binary", 52, 			// DATA	 HTTP POST binary data (H)
			"--data-urlencode", 53, 		// DATA	 HTTP POST data url encoded (H)
			"-D", 6,
			"--dump-header", 6, 			// FILE  Write the headers to FILE
			"-F", 7,
			"--form", 7, 					// CONTENT  Specify HTTP multipart POST data (H)
			"--form-string", 71,			// STRING  Specify HTTP multipart POST data (H)
			"-G", 8,
			"--get", 8, 					// Send the -d data with a HTTP GET (H)
			"-H", 10,
			"--header", 10, 				// LINE   Pass custom header LINE to server (H)
			"-I", 11,
			"--head", 11, 					// Show document info only
			//			"--ignore-content-length", 12, // Ignore the HTTP Content-Length header
			"-k", 31,
			"--insecure", 31,				// Allow insecure server connections when using SSL
			"-L", 13,
			"--location", 13, 				// Follow redirects (H)
			"-m", 14,
			"--max-time", 14, 				// SECONDS  Maximum time allowed for the transfer
			//			"--no-keepalive", 15, 			// Disable keepalive use on the connection
			"-o", 16,
			"--output", 16, 				// FILE   Write to FILE instead of stdout
			"-x", 17,
			"--proxy", 17, 					// [PROTOCOL://]HOST[:PORT]  Use proxy on given port
			"-U", 18,
			"--proxy-user", 18, 			// USER[:PASSWORD]  Proxy user and password
			"-e", 19,
			"--referer", 19, 				// Referer URL (H)
			"--retry", 20, 					// NUM   Retry request NUM times if transient problems occur
			"--retry-delay", 21, 			// SECONDS  Wait SECONDS between retries
			"--retry-max-time", 22, 		// SECONDS  Retry only within this period
			"-s", 23,
			"--silent", 23, 				// Silent mode (don't output anything)
			"--stderr", 24, 				// FILE   Where to redirect stderr (use "-" for stdout)
			"-u", 28,
			"--user", 28, 					// USER[:PASSWORD]  Server user and password
			"--url", 25, 					// URL	   URL to work with
			"-A", 26,
			"--user-agent", 26, 			// STRING  Send User-Agent STRING to server (H)
			"-X", 27, 
			"--request", 27,				// COMMAND  Specify request command to use
			"--x-max-download", 29,			// BYTES Maximum bytes allowed for the download
			"--x-tags", 30,					// DATA extra key-value pairs, storage only
			"", 0 // placeholder
			);

	private static final String BOUNDARY = "------------aia113jBkadk7289";
	private static final byte[] NEWLINE = "\r\n".getBytes();

	private final List<String> options = new ArrayList<String>();
	private final Map<String, IO> iomap = new HashMap<String, IO>();
	private final Map<String, String> tags = new LinkedHashMap<String, String>();
	private final Map<String, String> headers = new LinkedHashMap<String, String>();
	private final List<List<String[]>> responseHeaders = new ArrayList<List<String[]>>(4);
	private final List<URL> locations = new ArrayList<URL>(4);
	private long startTime;
	private long execTime;
	private int httpCode;
	private byte[] rawStdout;

	public CUrl() {}

	public CUrl(String url) {
		this.url(url);
	}

	/**
	 * Specify 0~N options, please refer to https://curl.haxx.se/docs/manpage.html
	 * Note: the option name and corresponding value must be divided into two arguments, rather than one single string seperated by space
	 * @param options e.g. opt("-H", "X-Requested-With: XMLHttpRequest")
	 */
	public final CUrl opt(String... options) {
		for (String o: options) {
			if (o.startsWith("'") && o.endsWith("'")) o = o.substring(1, o.length() - 1);
			this.options.add(o);
		}
		return this;
	}

	public final CUrl url(String url) {
		return opt("--url", url);
	}

	/**
	 * Follow redirection automatically, false be default.
	 * Only apply to HTTP CODE 30x
	 */
	public final CUrl location() {
		return opt("-L");
	}

	/**
	 * Specify the proxy server
	 */
	public final CUrl proxy(String host, int port) {
		return opt("-x", host + ":" + port);
	}

	/**
	 * Allow insecure server connections when using HTTPS
	 */
	public final CUrl insecure() {
		return opt("-k");
	}

	/**
	 * Specify retry related options, default values are 0
	 * @param retry Retry times
	 * @param retryDelay The interval between two retries (in second)
	 * @param retryMaxTime The max retry time in second, 0 means infinite
	 */
	public final CUrl retry(int retry, float retryDelay, float retryMaxTime) {
		return opt("--retry", Integer.toString(retry), 
				"--retry-delay", Float.toString(retryDelay),
				"--retry-max-time", Float.toString(retryMaxTime));
	}

	/**
	 * Specify timeout, default values are 0
	 * @param connectTimeoutSeconds Connection timeout in second
	 * @param readTimeoutSeconds Read timeout in second
	 */
	public final CUrl timeout(float connectTimeoutSeconds, float readTimeoutSeconds) {
		return opt("--connect-timeout", Float.toString(connectTimeoutSeconds), 
				"--max-time", Float.toString(readTimeoutSeconds));
	}

	/**
	 * Add a custom request header
	 * @param headerLine Syntax:
	 *  "Host: baidu.com": add/set a request header-value pair
	 *  "Accept:": delete a previously added request header
	 *  "X-Custom-Header;": add/set a request header with empty value
	 */
	public final CUrl header(String headerLine) {
		return opt("-H", headerLine);
	}

	public final CUrl headers(Map<String, ?> headers) {
		for (Map.Entry<String, ?> kv: headers.entrySet()) {
			Object k = kv.getKey(), v = kv.getValue();
			opt("-H", v == null ? k + ":" : v.toString().length() == 0 ? k + ";" : k + ": " + v);
		}
		return this;
	}

	/**
	 * Add post data. The data among multiple calls will be joined with '&amp;'
	 * @param data if data start with '@', then the following part will be treated as file path
	 */
	public final CUrl data(String data) {
		return data(data, false);
	}

	/**
	 * Add post data. The data among multiple calls will be joined with '&amp;'
	 * @param data å¦‚æžœdataä»¥'@'å¼€å¤´ä¸”raw=falseï¼Œåˆ™å�Žé�¢éƒ¨åˆ†ä½œä¸ºæ–‡ä»¶å��ï¼Œæ•°æ�®ç”±è¯¥æ–‡ä»¶è¯»å…¥
	 * @param raw å¦‚ä¸ºçœŸåˆ™ä¸�å¯¹'@'å�šç‰¹æ®Šå¤„ç�†
	 */
	public final CUrl data(String data, boolean raw) {
		return opt(raw ? "--data-raw" : "-d", data);
	}

	/**
	 * ä»Žinputä¸­è¯»å�–æ•°æ�®ä½œä¸ºpostæ•°æ�®
	 * Read data from input and use as post data
	 * @param input
	 * @param binary å¦‚ä¸ºçœŸåˆ™è¯»å�–æ•°æ�®ä¸­çš„å›žè½¦æ�¢è¡Œç¬¦ä¼šä¿�ç•™ï¼Œå�¦åˆ™ä¼šè¢«åˆ é™¤
	 */
	public final CUrl data(IO input, boolean binary) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), input);
		return opt(binary ? "--data-binary" : "-d", "@" + key);
	}

	/**
	 * æ·»åŠ urlencodeçš„postæ•°æ�®
	 * Add URL-encoded post data
	 * @param data, è¯­æ³•å¦‚ä¸‹/syntax:
	 *  "content": å¦‚contentä¸­ä¸�åŒ…å�«'=', '@'ï¼Œåˆ™ç›´æŽ¥æŠŠæ•´ä¸ªcontentä½œä¸ºæ•°æ�®æ•´ä½“è¿›è¡Œurlencode
	 *  "=content": '='å�Žé�¢çš„contentæ•´ä½“è¿›è¡Œurlencodeï¼Œä¸�å¤„ç�†ç‰¹æ®Šå­—ç¬¦ï¼Œç¬¬ä¸€ä¸ª'='ä¸�åŒ…å�«åœ¨æ•°æ�®å†…å®¹ä¸­
	 *  "name1=value1[&amp;name2=value2...]": æŒ‰ç…§'&amp;'æ‹†åˆ†å�Žï¼Œå¯¹æ¯�ä¸ªå€¼è¿›è¡Œurlencodeï¼Œæ³¨æ„�é”®ä¸�è¿›è¡Œå¤„ç�†
	 *  "@filename": '@'å�Žé�¢çš„éƒ¨åˆ†ä½œä¸ºæ–‡ä»¶å��ï¼Œä»Žæ–‡ä»¶ä¸­è¯»å�–å†…å®¹å¹¶è¿›è¡Œurlencodeï¼Œå›žè½¦æ�¢è¡Œä¿�ç•™
	 *  "name@filename": è¯»å�–'@'å�Žé�¢çš„æ–‡ä»¶å†…å®¹ä½œä¸ºå€¼è¿›è¡Œurlencodeï¼Œå¹¶ä»¥nameä¸ºé”®
	 * @param charset urlencodeä½¿ç”¨çš„å­—ç¬¦é›†ï¼Œå¦‚ä¸ºnullåˆ™é»˜è®¤ä½¿ç”¨"UTF-8"
	 */
	public final CUrl data(String data, String charset) {
		return opt("--data-urlencode" + (charset != null ? "-" + charset : ""), data);
	}

	/**
	 * å�‘èµ·postæ–‡ä»¶ä¸Šä¼ ï¼Œæ·»åŠ ä¸€ä¸ªè¡¨å�•é¡¹
	 * Issue a form based upload and add a form item
	 * @param name è¡¨å�•é¡¹å��
	 * @param content å¦‚é¦–å­—æ¯�ä¸º'@'æˆ–'&lt;'åˆ™ä»ŽæŒ‡å®šçš„æ–‡ä»¶è¯»å�–æ•°æ�®è¿›è¡Œä¸Šä¼ ã€‚
	 *  '@'å’Œ'&lt;'çš„åŒºåˆ«åœ¨äºŽï¼Œ'@'çš„æ–‡ä»¶å†…å®¹ä½œä¸ºæ–‡ä»¶é™„ä»¶ä¸Šä¼ ï¼Œ'&lt;'çš„æ–‡ä»¶å†…å®¹ä½œä¸ºæ™®é€šè¡¨å�•é¡¹
	 */
	public final CUrl form(String name, String content) {
		return opt("-F", name + "=" + content);
	}

	/**
	 * å�‘èµ·postæ–‡ä»¶ä¸Šä¼ ï¼Œæ·»åŠ ä¸€ä¸ªæ–‡ä»¶ä¸Šä¼ çš„è¡¨å�•é¡¹
	 * Issue a form based upload and add a file item
	 * @param name è¡¨å�•é¡¹å��
	 * @param input ä¸Šä¼ çš„æ•°æ�®IO
	 */
	public final CUrl form(String name, IO input) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), input);
		return opt("-F", name + "=@" + key);
	}

	/**
	 * å�‘èµ·postæ–‡ä»¶ä¸Šä¼ ï¼Œæ·»åŠ 1~Nä¸ªé�žæ–‡ä»¶è¡¨å�•é¡¹ï¼Œæ³¨æ„�æ­¤æ–¹æ³•ä¸�å¯¹'@'è¿›è¡Œç‰¹æ®Šå¤„ç�†
	 * @param formString è¯­æ³•ä¸º"name1=value1[&amp;name2=value2...]"
	 */
	public final CUrl form(String formString) {
		return opt("--form-string", formString);
	}

	/** 
	 * è¾“å‡ºCookieåˆ°ç»™å®šçš„æ–‡ä»¶
	 * Output Cookie to given file path
	 * @param output æ–‡ä»¶è·¯å¾„ï¼Œä½¿ç”¨'-'è¡¨ç¤ºè¾“å‡ºåˆ°æ ‡å‡†è¾“å‡ºã€‚é»˜è®¤ä¸�è¾“å‡º
	 */
	public final CUrl cookieJar(String output) {
		return opt("-c", output);
	}

	/** 
	 * è¾“å‡ºCookieåˆ°ç»™å®šçš„æ•°æ�®IO
	 * Output Cookie to given IO object
	 * @param output æ•°æ�®IOï¼Œæ³¨æ„�cookieJarçš„è¾“å‡ºä¼šæ¸…é™¤outputä¸­çš„åŽŸæœ‰å†…å®¹
	 */
	public final CUrl cookieJar(IO output) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), output);
		return opt("-c", key);
	}

	/** 
	 * æ·»åŠ è¯·æ±‚Cookie
	 * Add custom Cookies in request
	 * @param input æ ¼å¼�ä¸º"NAME1=VALUE1; NAME2=VALUE2"çš„Cookieé”®å€¼å¯¹ã€‚
	 *  å¦‚å­—ä¸²ä¸­ä¸�åŒ…å�«'='åˆ™ä½œä¸ºè¾“å…¥æ–‡ä»¶å��ï¼›
	 *  å¦‚ä¼ å…¥ç©ºå­—ç¬¦ä¸²åˆ™ä»…æ¸…ç©ºå½“å‰�çº¿ç¨‹çš„Cookie
	 */
	public final CUrl cookie(String input) {
		return opt("-b", input);
	}

	/**
	 * è¯»å�–æ•°æ�®IOå¹¶æ·»åŠ è¯·æ±‚Cookieã€‚
	 * æ³¨æ„�CUrlä¼šè‡ªåŠ¨ä¸ºå�Œä¸€çº¿ç¨‹å†…çš„å¤šæ¬¡è¯·æ±‚ç»´æŒ�Cookie
	 * @param input
	 * @return
	 */
	public final CUrl cookie(IO input) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), input);
		return opt("-b", key);
	}

	/** 
	 * å€¾å�°åŽŸå§‹å“�åº”å¤´åˆ°ç»™å®šçš„æ–‡ä»¶
	 * Dump raw response headers to specified file path
	 * @param output è¾“å‡ºæ–‡ä»¶çš„è·¯å¾„ï¼Œä½¿ç”¨'-'è¡¨ç¤ºè¾“å‡ºåˆ°æ ‡å‡†è¾“å‡ºã€‚é»˜è®¤ä¸�è¾“å‡ºã€‚ 
	 */
	public final CUrl dumpHeader(String output) {
		return opt("-D", output);
	}

	/** 
	 * å€¾å�°åŽŸå§‹å“�åº”å¤´åˆ°ç»™å®šçš„æ•°æ�®IO
	 * @param output  
	 */
	public final CUrl dumpHeader(IO output) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), output);
		return opt("-D", key);
	}

	public final CUrl cert(IO certificate, String password) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), certificate);
		return opt("-E", key + ":" + password);
	}

	/** 
	 * é‡�å®šå�‘æ ‡å‡†é”™è¯¯è¾“å‡ºåˆ°ç»™å®šçš„æ–‡ä»¶
	 * Redirect stderr to specified file path, use '-' for stdout
	 * @param output è¾“å‡ºæ–‡ä»¶è·¯å¾„ã€‚ä½¿ç”¨'-'è¡¨ç¤ºè¾“å‡ºåˆ°æ ‡å‡†è¾“å‡ºã€‚é»˜è®¤è¾“å‡ºåˆ°æ ‡å‡†è¾“å‡ºã€‚
	 */
	public final CUrl stderr(String output) {
		return opt("--stderr", output); // output can be an OutputStream/File/path_to_file
	}

	/** 
	 * é‡�å®šå�‘æ ‡å‡†é”™è¯¯è¾“å‡ºåˆ°ç»™å®šçš„æ•°æ�®IO
	 * @param output
	 */
	public final CUrl stderr(IO output) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), output);
		return opt("--stderr", key);
	}

	/** 
	 * è¾“å‡ºåº”ç­”æ•°æ�®åˆ°ç»™å®šæ–‡ä»¶ã€‚æ³¨æ„�æ ‡å‡†è¾“å‡ºé»˜è®¤å�³ä¸ºexecæ–¹æ³•çš„è¿”å›žå€¼ã€‚
	 * Output response data to specified fila path
	 * @param output è¾“å‡ºæ–‡ä»¶è·¯å¾„ã€‚ä½¿ç”¨'-'è¡¨ç¤ºè¾“å‡ºåˆ°æ ‡å‡†è¾“å‡ºã€‚é»˜è®¤è¾“å‡ºåˆ°æ ‡å‡†è¾“å‡ºã€‚
	 */
	public final CUrl output(String output) {
		return opt("-o", output); // output can be an OutputStream/File/path_to_file
	}

	/** 
	 * è¾“å‡ºåº”ç­”æ•°æ�®åˆ°ç»™å®šæ•°æ�®IO
	 * @param output
	 */
	public final CUrl output(IO output) {
		String key;
		iomap.put(key = "IO#" + iomap.size(), output);
		return opt("-o", key);
	}

	/**
	 * æ·»åŠ ä¸€ä¸ªæ•°æ�®IOï¼Œå�¯ä½œä¸ºæ•°æ�®è¾“å…¥æˆ–æ•°æ�®è¾“å‡ºï¼Œåœ¨--dataç­‰å�‚æ•°å€¼ä¸­å¼•ç”¨
	 * @param key
	 * @param io
	 * @return
	 */
	public final CUrl io(String key, IO io) {
		iomap.put(key, io);
		return this;
	}

	public static java.net.CookieStore getCookieStore() {
		return cookieStore;
	}

	/**
	 * Save all cookies binding with current thread to the specified IO object.
	 * The output format is compatible with CURL tool.
	 * @param output
	 */
	public static void saveCookies(IO output) {
		StringBuilder sb = new StringBuilder();
		for (HttpCookie cookie: cookieStore.getCookies()) {
			long expire = cookie.getMaxAge() <= 0 || cookie.getMaxAge() >= Integer.MAX_VALUE ?
					Integer.MAX_VALUE : cookie.getMaxAge() + System.currentTimeMillis() / 1000L;
			sb.append(cookie.getDomain()).append('\t')
			.append("FALSE").append('\t')
			.append(cookie.getPath()).append('\t')
			.append(cookie.getSecure() ? "TRUE" : "FALSE").append('\t')
			.append(expire).append('\t')
			.append(cookie.getName()).append('\t')
			.append(cookie.getValue()).append('\n');
		}
		writeOutput(output, Util.s2b(sb.toString(), null), false);
	}

	/**
	 * Load cookies from the specified IO object to the cookie-store binding with current thread
	 * @param input
	 */
	public static void loadCookies(IO input) {
		String s = Util.b2s(readInput(input), null, null);
		BufferedReader br = new BufferedReader(new StringReader(s));
		try {
			for (String line = br.readLine(), l[]; line != null; line = br.readLine()) {
				if (line.trim().length() == 0 || line.startsWith("# ") || (l = line.split("\t")).length < 7) continue;
				HttpCookie cookie = new HttpCookie(l[5], l[6]);
				cookie.setDomain(l[0]);
				cookie.setPath(l[2]);
				cookie.setSecure("TRUE".equals(l[3]));
				long expire = Long.parseLong(l[4]);
				cookie.setMaxAge(expire >= Integer.MAX_VALUE ? Integer.MAX_VALUE : expire * 1000L - System.currentTimeMillis());
				if (!cookie.hasExpired()) cookieStore.add(null, cookie);
			}
		} catch (Exception ignored) { } // should not happen
	}

	/**
	 * Get all options as CURL command-line
	 */
	public final String toString() {
		StringBuilder sb = new StringBuilder("curl");
		for (String s: options) {
			sb.append(' ').append(ptnOptionName.matcher(s).matches() ? s : '"' + s + '"');
		}
		if (iomap.size() > 0) sb.append("\r\n> IOMap: ").append(iomap);
		return sb.toString();
	}

	/**
	 * Get all options, filled after exec.
	 * You can change one or more options and re-exec the same CUrl instance, for example, switch proxy server.
	 * @return
	 */
	public final List<String> getOptions() {
		return options;
	}

	public final Map<String, String> getTags() {
		return tags;
	}

	/**
	 * Get request headers, filled after exec.
	 * @return
	 */
	public final Map<String, String> getHeaders() {
		return headers;
	}

	/**
	 * Get headers of all responses including redirection(s) in one request.
	 * In case --location is not specified (default), it's always exactly one element.
	 * @return
	 */
	public final List<List<String[]>> getResponseHeaders() {
		return responseHeaders;
	}

	/**
	 * Get total time-consuming including retrying in millisecond.
	 * @return
	 */
	public final long getExecTime() {
		return execTime;
	}

	/**
	 * Get HTTP status code of last response, i.e. 200, 302 etc.
	 * @return
	 */
	public final int getHttpCode() {
		return httpCode;
	}

	public final <T> T getStdout(Resolver<T> resolver, T fallback) {
		try { return resolver.resolve(httpCode, rawStdout); } catch (Throwable ignored) {}
		return fallback;
	}

	/**
	 * Get all destination URLs including redirection(s) in one request.
	 * In case --location is not specified (default), it's always exactly one element.
	 * @return
	 */
	public final List<URL> getLocations() {
		return locations;
	}

	/**
	 * è§£æž�å�‚æ•°ï¼Œæ‰§è¡Œè¯·æ±‚ï¼Œå¹¶å°†æ ‡å‡†è¾“å‡ºä»¥ç»™å®šçš„encodingè§£ç �ä¸ºå­—ç¬¦ä¸²
	 * Parse options and execute the requestã€‚Decode the raw response to String with given character-encoding
	 * @param encodingï¼Œå¦‚ä¼ å…¥nullåˆ™é»˜è®¤ä½¿ç”¨"UTF-8"
	 * @return æ ‡å‡†è¾“å‡ºæ•°æ�®ï¼Œä»¥encodingç¼–ç �ä¸ºå­—ç¬¦ä¸²
	 */
	public final String exec(String encoding) {
		return exec(encoding != null ? new ToStringResolver(encoding) : UTF8, null);
	}

	/**
	 * è§£æž�å�‚æ•°ï¼Œæ‰§è¡Œè¯·æ±‚ï¼Œè¿”å›žåŽŸå§‹å­—èŠ‚æ•°ç»„
	 * Parse options and execute the request, return raw response.
	 * @return æ ‡å‡†è¾“å‡ºæ•°æ�®
	 */
	public final byte[] exec() {
		return exec(RAW, null);
	}

	/**
	 * è§£æž�å�‚æ•°å¹¶æ‰§è¡Œè¯·æ±‚
	 * é»˜è®¤ä»…åŒ…å�«åº”ç­”æ•°æ�®ã€‚æŒ‡å®š"--silent"å�‚æ•°åˆ™ä¸�è¾“å‡ºã€‚
	 * @param resolver è¾“å‡ºè§£æž�å™¨
	 * @param fallback é»˜è®¤è¿”å›žå€¼
	 * @return å°†æ ‡å‡†è¾“å‡ºä¸­çš„æ•°æ�®ä½¿ç”¨è§£æž�å™¨è½¬æ�¢ä¸ºå¯¹è±¡ã€‚å¦‚å¤±è´¥ï¼Œåˆ™è¿”å›žfallback
	 */
	public final <T> T exec(Resolver<T> resolver, T fallback) {
		startTime = System.currentTimeMillis();
		tags.clear();
		headers.clear();
		responseHeaders.clear();
		locations.clear();
		execTime = 0;
		httpCode = -1;
		rawStdout = null;
		Proxy proxy = Proxy.NO_PROXY;
		String url = null, redirect = null, method = null, cookie = null, charset = "UTF-8", cert = null;
		final MemIO stdout = new MemIO();
		IO stderr = stdout, output = stdout, cookieJar = null, dumpHeader = null;
		StringBuilder dataSb = new StringBuilder();
		Map<String, Util.Ref<String>> form = new LinkedHashMap<String, Util.Ref<String>>();
		float connectTimeout = 0, maxTime = 0, retryDelay = 0, retryMaxTime = 0;
		int retry = 0, maxDownload = 0;
		boolean location = false, silent = false, mergeData = false, insecure = false;
		//		boolean ignoreContentLength = false, noKeepAlive = false;
		Util.mapPut(headers, "Accept", "*/*", "User-Agent", DEFAULT_USER_AGENT);
		iomap.put("-", stdout);
		Throwable lastEx = null;
		for (int i = 0, n = options.size(); i < n; i++) {
			String opt = options.get(i);
			if (opt.startsWith("http://") || opt.startsWith("https://")) {
				url = opt;
				continue;
			}
			if (opt.startsWith("--data-urlencode-")) {
				charset = opt.substring(17);
				opt = "--data-urlencode";
			}
			switch (Util.mapGet(optMap, opt, -1)) {
			case 32: // --cert  <certificate[:password]> Client certificate file and password
				cert = options.get(++i);
				break;
			case 1: // --compressed  Request compressed response (using deflate or gzip)
				headers.put("Accept-Encoding", "gzip, deflate");
				break;
			case 2: // --connect-timeout  SECONDS  Maximum time allowed for connection
				connectTimeout = Float.parseFloat(options.get(++i)); 
				break;
			case 3: // --cookie  STRING/FILE  Read cookies from STRING/FILE (H)
				cookie = options.get(++i);
				break;
			case 4: // --cookie-jar  FILE  Write cookies to FILE after operation (H)
				cookieJar = getIO(options.get(++i)); 
				break;
			case 5: // --data  DATA	 HTTP POST data (H)
				String data = options.get(++i);
				if (data.startsWith("@")) data = Util.b2s(readInput(getIO(data.substring(1))), null, null).replaceAll("[\r\n]+", "");
				mergeData = dataSb.length() > 0;
				dataSb.append(mergeData ? "&" : "").append(data);
				break;
			case 51: // --data-raw  DATA	 not handle "@"
				mergeData = dataSb.length() > 0;
				dataSb.append(mergeData ? "&" : "").append(options.get(++i));
				break;
			case 52: // --data-binary  DATA	 not stripping CR/LF
				data = options.get(++i);
				if (data.startsWith("@")) data = Util.b2s(readInput(getIO(data.substring(1))), null, null);
				mergeData = dataSb.length() > 0;
				dataSb.append(mergeData ? "&" : "").append(data);
				break;
			case 53: // --data-urlencode 
				mergeData = dataSb.length() > 0;
				data = options.get(++i);
				int idx, atIdx;
				switch (idx = data.indexOf("=")) {
				case -1: // no '='
					if ((atIdx = data.indexOf("@")) >= 0) { // [name]@filename
						String prefix = atIdx > 0 ? data.substring(0, atIdx) + "=" : "";
						try { 
							data = prefix + URLEncoder.encode(Util.b2s(readInput(getIO(data.substring(atIdx + 1))), null, ""), charset);
						} catch (Exception e) {
							lastEx = e;
						}
						break;
					} // else fall through
				case 0: // =content
					try { 
						data = URLEncoder.encode(data.substring(idx + 1), charset);
					} catch (Exception e) {
						lastEx = e;
					}
					break;
				default: // name=content
					Map<String, String> m = Util.split(data, "&", "=", new LinkedHashMap<String, String>());
					for (Map.Entry<String, String> en: m.entrySet()) {
						try { en.setValue(URLEncoder.encode(en.getValue(), "UTF-8")); } catch (Exception ignored) { }
					}
					data = Util.join(m, "&", "=");
				}
				dataSb.append(mergeData ? "&" : "").append(data);
				break;
			case 6: // --dump-header  FILE  Write the headers to FILE
				dumpHeader = getIO(options.get(++i)); 
				break;
			case 7: // --form  CONTENT  Specify HTTP multipart POST data (H)
				data = options.get(++i);
				idx = data.indexOf('=');
				form.put(data.substring(0, idx), new Util.Ref<String>(1, data.substring(idx + 1)));
				break;
			case 71: // --form-string  STRING  Specify HTTP multipart POST data (H)
				for (String[] pair: Util.split(options.get(++i), "&", "=")) {
					form.put(pair[0], new Util.Ref<String>(pair[1]));
				}
				break;
			case 8: // --get  Send the -d data with a HTTP GET (H)
				method = "GET";
				break;
			case 10: // --header  LINE   Pass custom header LINE to server (H)
				String[] hh = options.get(++i).split(":", 2);
				String name = hh[0].trim();
				if (hh.length == 1 && name.endsWith(";")) { // "X-Custom-Header;"
					headers.put(name.substring(0, name.length() - 1), "");
				} else if (hh.length == 1) { // "Host:"
					headers.remove(name);
				} else { // "Host: baidu.com"
					headers.put(name, hh[1].trim());
				}
				break;
			case 11: // --head  Show document info only
				method = "HEAD";
				break;
				//			case 12: // --ignore-content-length  Ignore the HTTP Content-Length header
				//				ignoreContentLength = true;
				//				break;
			case 13: // --location  Follow redirects (H)
				location = true;
				break;
			case 14: // --max-time  SECONDS  Maximum time allowed for the transfer
				maxTime = Float.parseFloat(options.get(++i)); 
				break;
				//			case 15: // --no-keepalive  Disable keepalive use on the connection
				//				noKeepAlive = true;
				//				break;
			case 16: // --output  FILE   Write to FILE instead of stdout
				output = getIO(options.get(++i)); 
				break;
			case 17: // --proxy  [PROTOCOL://]HOST[:PORT]  Use proxy on given port
				String[] pp = options.get(++i).split(":");
				InetSocketAddress addr = new InetSocketAddress(pp[0], pp.length > 1 ? Integer.parseInt(pp[1]) : 1080);
				proxy = new Proxy(Proxy.Type.HTTP, addr);
				break;
			case 18: // --proxy-user  USER[:PASSWORD]  Proxy user and password
				final String proxyAuth = options.get(++i);
				headers.put("Proxy-Authorization", "Basic " + Util.base64Encode(proxyAuth.getBytes()));
				Authenticator.setDefault(new Authenticator() {
					@Override
					protected PasswordAuthentication getPasswordAuthentication() {
						String[] up = proxyAuth.split(":");
						return new PasswordAuthentication(up[0], (up.length > 1 ? up[1] : "").toCharArray());
					}
				});
				break;
			case 19: // --referer  Referer URL (H)
				headers.put("Referer", options.get(++i));
				break;
			case 20: // --retry  NUM   Retry request NUM times if transient problems occur
				retry = Integer.parseInt(options.get(++i));
				break;
			case 21: // --retry-delay  SECONDS  Wait SECONDS between retries
				retryDelay = Float.parseFloat(options.get(++i));
				break;
			case 22: // --retry-max-time  SECONDS  Retry only within this period
				retryMaxTime = Float.parseFloat(options.get(++i));
				break;
			case 23: // --silent  Silent mode (don't output anything)
				silent = true;
				break;
			case 24: // --stderr  FILE   Where to redirect stderr (use "-" for stdout)
				stderr = getIO(options.get(++i));
				break;
			case 25: // --url  URL	   URL to work with
				url = options.get(++i);
				break;
			case 26: // --user-agent  STRING  Send User-Agent STRING to server (H)
				headers.put("User-Agent", options.get(++i));
				break;
			case 27: // --request  COMMAND  Specify request command to use
				method = options.get(++i);
				break;
			case 28: // -u, --user USER[:PASSWORD]  Server user and password
				headers.put("Authorization", "Basic " + Util.base64Encode(options.get(++i).getBytes()));
				break;
			case 29: // --x-max-download  BYTES Maximum bytes allowed for the download
				maxDownload = Integer.parseInt(options.get(++i));
				break;
			case 30: // --x-tags  DATA extra key-value pairs, storage only
				Util.split(options.get(++i), "&", "=", tags);
				break;
			case 31: //
				insecure = true;
				break;
			default: lastEx = new IllegalArgumentException("option " + opt + ": is unknown");
			}
			if (lastEx != null) 
				return error(stdout, stderr, lastEx, silent, resolver, fallback);
		}
		if (url == null) {
			lastEx = new IllegalArgumentException("no URL specified!");
			return error(stdout, stderr, lastEx, silent, resolver, fallback);
		}
		if (dataSb.length() > 0 && form.size() > 0 
				|| dataSb.length() > 0 && "HEAD".equals(method) 
				|| form.size() > 0 && "HEAD".equals(method)) {
			lastEx = new IllegalArgumentException("Warning: You can only select one HTTP request!");
			return error(stdout, stderr, lastEx, silent, resolver, fallback);
		}
		String dataStr = "";
		if (form.size() > 0) {
			if (method == null) method = "POST";
		} else if (dataSb.length() > 0) {
			dataStr = !mergeData ? dataSb.toString() 
					: Util.join(Util.split(dataSb.toString(), "&", "=", new LinkedHashMap<String, String>()), "&", "=");
			if (method == null) method = "POST";
		}
		if (method == null) method = "GET";
		//		if (!noKeepAlive) headers.put("Connection", "keep-alive");
		if (cookie != null) { // --cookie '' will clear the CookieStore
			cookieStore.removeAll();
			if (cookie.indexOf('=') > 0) {
				parseCookies(url, cookie);
			} else if (cookie.trim().length() > 0) {
				loadCookies(getIO(cookie));
			}
		}

		boolean needRetry = false;
		if (dataStr.length() > 0 && "GET".equals(method)) url += (url.contains("?") ? "&" : "?") + dataStr;
		URL urlObj = null;
		int retryLeft = retry;
		do {
			try {
				if (redirect != null) {
					urlObj = new URL(urlObj, redirect);
					method = "GET";
				} else {
					urlObj = new URL(url);
				}
				if (retryLeft == retry) { // add at first time
					if (locations.size() > 51) {
						redirect = null;
						throw new RuntimeException("Too many redirects."); 
					}
					locations.add(urlObj); 
					responseHeaders.add(new ArrayList<String[]>());
				}
				HttpURLConnection con = (HttpURLConnection) urlObj.openConnection(proxy);
				con.setRequestMethod(method);
				con.setUseCaches(false);
				con.setConnectTimeout((int) (connectTimeout * 1000f));
				con.setReadTimeout((int) (maxTime * 1000f));
				con.setInstanceFollowRedirects(false);
				if (con instanceof HttpsURLConnection) {
					if (insecure) {
						((HttpsURLConnection) con).setHostnameVerifier(insecureVerifier);
						((HttpsURLConnection) con).setSSLSocketFactory(insecureFactory);
					} else if (cert != null) {
						int idx = cert.lastIndexOf(':');
						((HttpsURLConnection) con).setSSLSocketFactory(getSocketFactory(getIO(cert.substring(0, idx)), cert.substring(idx + 1)));
					}
				}
				for (Map.Entry<String, String> h: headers.entrySet()) con.setRequestProperty(h.getKey(), h.getValue());
				if ("POST".equals(method)) {
					con.setDoInput(true);
					con.setDoOutput(true);
					byte[] data;
					if (form.size() > 0) { // it's upload
						con.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + BOUNDARY);
						ByteArrayOutputStream os = new ByteArrayOutputStream();
						byte[] bb;
						for (Map.Entry<String, Util.Ref<String>> en: form.entrySet()) {
							String name = en.getKey(), filename = null, type = null;
							Util.Ref<String> val = en.getValue();
							if (val.getInt() == 1) {
								String[][] ll = Util.split(val.get(), ";", "=");
								String _1st = unquote(ll[0][0].trim());
								for (int j = 1; j < ll.length; j++) {
									if (ll[j].length > 1 && "type".equals(ll[j][0].trim())) {
										type = unquote(ll[j][1].trim());
									} else if (ll[j].length > 1 && "filename".equals(ll[j][0].trim())) {
										filename = unquote(ll[j][1].trim());
									}
								}
								if (_1st.startsWith("@") || _1st.startsWith("<")) { // it's file
									IO in = getIO(_1st.substring(1));
									File f = in instanceof FileIO ? ((FileIO) in).f : null;
									filename = _1st.startsWith("<") ? null : 
										filename != null ? filename : f != null ? f.getAbsolutePath() : name;
										if (f != null && !(f.exists() && f.isFile() && f.canRead()))
											throw new IllegalArgumentException("couldn't open file \"" + filename + "\"");
										bb = readInput(in);
								} else {
									bb = Util.s2b(_1st, null);
								}
							} else {
								bb = Util.s2b(val.get(), null);
							}
							os.write(("--" + BOUNDARY + "\r\n").getBytes());
							os.write(("Content-Disposition: form-data; name=\"" + name + "\"").getBytes());
							if (filename != null) os.write(("; filename=\"" + filename + "\"").getBytes());
							if (type != null) os.write(("\r\nContent-Type: " + type).getBytes());
							os.write(NEWLINE);
							os.write(NEWLINE);
							os.write(bb);
							os.write(NEWLINE);
						}
						os.write(("--" + BOUNDARY + "--\r\n").getBytes());
						data = os.toByteArray();
					} else {
						data = Util.s2b(dataStr, null); // UTF-8
						//						if (!ignoreContentLength) {
						con.setRequestProperty("Content-Length", Integer.toString(data.length));
						if (!headers.containsKey("Content-Type")) {
							con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
						}
					}
					try {
						OutputStream os = con.getOutputStream();
						os.write(data);
						os.flush();
					} catch (Exception ex) { // connect timeout
						throw new Recoverable(ex, -1);
					}
				}
				redirect = null;
				httpCode = con.getResponseCode();
				if (httpCode >= 300 && httpCode < 400) redirect = con.getHeaderField("Location");
				if (redirect != null) retryLeft = retry;
				InputStream is;
				try {
					is = con.getInputStream();
				} catch (Exception e) {
					if (httpCode == 407 && proxy != Proxy.NO_PROXY && "https".equals(urlObj.getProtocol()) 
							&& headers.containsKey("Proxy-Authorization")) {
						throw new RuntimeException(e.getMessage() + "\nTry using VM argument \"-Djdk.http.auth.tunneling.disabledSchemes=\"", e);
					}
					if (redirect == null) lastEx = e;
					is = con.getErrorStream();
				}
				if (is == null && lastEx != null) throw lastEx;
				byte bb[] = Util.readStream(is, maxDownload, true), b0, b1;
				if (maxDownload <= 0 && bb != null && bb.length > 2) {
					if ((b0 = bb[0]) == 0x1F && bb[1] == (byte) 0x8B) is = new GZIPInputStream(new ByteArrayInputStream(bb)); // gzip
					if (b0 == 0x78 && ((b1 = bb[1]) == 0x01 || b1 == 0x5E || b1 == (byte) 0x9C || b1 == (byte) 0xDA)) is = new InflaterInputStream(new ByteArrayInputStream(bb)); // deflate/zlib
					if (is instanceof InflaterInputStream) bb = Util.readStream(is, false);
				}
				int idx = locations.size() - 1;
				fillResponseHeaders(con, responseHeaders.get(idx));
				if (dumpHeader != null) dumpHeader(responseHeaders.get(idx), dumpHeader); 
				if (bb != null && bb.length > 0) writeOutput(output, bb, output == dumpHeader);
				if (lastEx != null) throw lastEx;
				if (redirect == null || !location) {
					rawStdout = stdout.toByteArray();
					execTime = System.currentTimeMillis() - startTime;
					if (cookieJar != null) saveCookies(cookieJar);
					return silent ? fallback : getStdout(resolver, fallback);
				}
			} catch (Throwable e) {
				needRetry = isRecoverable(e.getClass());
				lastEx = e instanceof Recoverable ? e.getCause() : e;
				if (needRetry && retryLeft > 0 && retryDelay > 0) 
					try { Thread.sleep((long) (retryDelay * 1000d)); } catch (Exception ignored) {}
			}
		} while (location && redirect != null || needRetry && --retryLeft >= 0 
				&& (retryMaxTime <= 0 || System.currentTimeMillis() - startTime < (long) (retryMaxTime * 1000d)));
		return error(stdout, stderr, lastEx, silent, resolver, fallback);
	}

	/** æ ¹æ�®keyèŽ·å�–å¯¹åº”IOï¼Œå¦‚æžœiomapä¸­æ²¡æœ‰ï¼Œåˆ™keyä½œä¸ºæ–‡ä»¶è·¯å¾„åˆ›å»ºä¸€ä¸ªFileIO  */
	private IO getIO(String key) {
		IO io;
		return (io = iomap.get(key)) == null ? new FileIO(key) : io;
	}

	private <T> T error(IO stdout, IO stderr, Throwable ex, boolean silent, Resolver<T> rr, T fallback) {
		writeOutput(stderr, Util.dumpStackTrace(ex, false).getBytes(), true);
		httpCode = ex instanceof Recoverable ? ((Recoverable) ex).httpCode : -1;
		rawStdout = ((MemIO) stdout).toByteArray();
		execTime = System.currentTimeMillis() - startTime;
		return silent ? fallback : getStdout(rr, fallback);
	}

	private static void parseCookies(String url, String input) {
		String host = null;
		try { host = new URI(url).getHost(); } catch (Exception ignored) { }
		for (String[] pair: Util.split(input, ";", "=")) {
			HttpCookie cookie = new HttpCookie(pair[0], Util.urlDecode(pair[1], "UTF-8"));
			cookie.setDomain(host);
			cookie.setPath("/");
			cookie.setSecure(false);
			cookieStore.add(null, cookie);
		}
	}

	private static String unquote(String s) {
		return s.startsWith("'") && s.endsWith("'") || s.startsWith("\"") && s.endsWith("\"") ?
				s.substring(1, s.length() - 1) : s;
	}

	private static void fillResponseHeaders(HttpURLConnection con, List<String[]> headers) {
		headers.clear();
		Object responses = Util.getField(con, null, "responses", null, true); // sun.net.www.MessageHeader
		if (responses == null) { // con is sun.net.www.protocol.https.HttpsURLConnectionImpl
			Object delegate = Util.getField(con, null, "delegate", null, true);
			if (delegate != null) responses = Util.getField(delegate, null, "responses", null, true);
		}
		String[] keys, values;
		Integer nkeys;
		if (responses != null && (nkeys = (Integer) Util.getField(responses, null, "nkeys", null, true)) != null
				&& (keys = (String[]) Util.getField(responses, null, "keys", null, true)) != null
				&& (values = (String[]) Util.getField(responses, null, "values", null, true)) != null) {
			for (int i = 0; i < nkeys; i++) headers.add(new String[] { keys[i], values[i] });
		} else {
			try { headers.add(new String[] { null, con.getResponseMessage() }); } catch (Exception ignored) {}
			for (int i = 0; ; i++) {
				String k = con.getHeaderFieldKey(i), v = con.getHeaderField(i);
				if (k == null && v == null) break;
				headers.add(new String[] { k, v });
			}
		}
	}

	private static void dumpHeader(List<String[]> headers, IO dumpHeader) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		for (String[] kv: headers) 
			bos.write(((kv[0] != null ? kv[0] + ": " : "") + (kv[1] != null ? kv[1] : "") + "\r\n").getBytes());
		bos.write(NEWLINE);
		writeOutput(dumpHeader, bos.toByteArray(), false);
	}

	/** è¯»å�–IOä¸­çš„æ•°æ�®ï¼Œå¦‚ä¸�é€‚ç”¨æˆ–æ— æ•°æ�®åˆ™è¿”å›žç©ºæ•°ç»„ */
	private static byte[] readInput(IO in) {
		InputStream is = in.getInputStream();
		byte[] bb;
		if (is == null || (bb = Util.readStream(is, false)) == null) bb = new byte[0];
		in.close();
		return bb;
	}

	/** æŠŠæ•°æ�®è¾“å‡ºåˆ°IOï¼Œå¦‚ä¸�é€‚ç”¨åˆ™ç›´æŽ¥è¿”å›žã€‚å¦‚appendä¸ºtrueåˆ™å�‘æ•°æ�®IOæ·»åŠ ï¼Œå�¦åˆ™è¦†ç›–ã€‚*/
	private static void writeOutput(IO out, byte[] bb, boolean append) {
		out.setAppend(append);
		OutputStream os = out.getOutputStream();
		if (os == null) return;
		try {
			os.write(bb);
			os.flush();
		} catch (Exception e) {
			Util.logStderr("CUrl.writeOutput: out=%s,bb=%s,append=%s,ex=%s", out, bb, append, Util.dumpStackTrace(e, true));
		}
		out.close();
	}

	private static final HashSet<Class> RECOVERABLES = Util.listAdd(
			new HashSet<Class>(), 
			(Class) Recoverable.class, 
			ConnectException.class,
			HttpRetryException.class,
			SocketException.class,
			SocketTimeoutException.class,
			NoRouteToHostException.class);

	private static boolean isRecoverable(Class<? extends Throwable> errCls) {
		if (RECOVERABLES.contains(errCls)) return true;
		for (Class re: RECOVERABLES) if (re.isAssignableFrom(errCls)) return true;
		return false;
	}

	private static SSLSocketFactory getSocketFactory(IO cert, String password) throws Exception {
		TrustManager[] managers;
		if (cert == null) {
			managers = new TrustManager[] { new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() { return null; }
				public void checkClientTrusted(X509Certificate[] arg0, String arg1) {}
				public void checkServerTrusted(X509Certificate[] arg0, String arg1) {}
			}};
		} else {
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // JKS for java, BKS for android
			keyStore.load(cert.getInputStream(), password.toCharArray());
			cert.close();
			TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			factory.init(keyStore);
			managers = factory.getTrustManagers();
		}
		SSLContext sc = SSLContext.getInstance("TLS");
		sc.init(null, managers, new SecureRandom());
		return sc.getSocketFactory();
	}

	///////////////////////////// Inner Classes & static instances ///////////////////////////////////////

	public interface Resolver<T> {
		T resolve(int httpCode, byte[] responseBody) throws Throwable;
	}

	public static class ToStringResolver implements Resolver<String> {
		final private String charset;
		public ToStringResolver(String charset) { this.charset = charset; }
		@Override
		public String resolve(int httpCode, byte[] raw) throws Throwable { return new String(raw, charset); }
	}

	public static final Resolver<byte[]> RAW = new Resolver<byte[]>() {
		@Override
		public byte[] resolve(int httpCode, byte[] raw) { return raw; }
	};

	public static final ToStringResolver UTF8 = new ToStringResolver("UTF-8");
	public static final ToStringResolver GBK = new ToStringResolver("GBK");
	public static final ToStringResolver ISO_8859_1 = new ToStringResolver("ISO-8859-1");

	public interface IO {
		InputStream getInputStream();
		OutputStream getOutputStream();
		void setAppend(boolean append);
		void close();
	}

	public static final class WrappedIO implements IO {
		final InputStream is;
		final OutputStream os;
		public WrappedIO(String s, String charset) { this(Util.s2b(s, charset)); }
		public WrappedIO(byte[] byteArray) { this(new ByteArrayInputStream(byteArray)); }
		public WrappedIO(InputStream is) { this.is = is; this.os = null; }
		public WrappedIO(OutputStream os) { this.is = null; this.os = os; }
		public InputStream getInputStream() { return is; }
		public OutputStream getOutputStream() { return os; }
		public void setAppend(boolean append) {} // not supported
		public void close() {} // wrapper is not responsible for closing
		public String toString() { return "WrappedIO<" + is + "," + os + ">"; }
	}

	public static final class FileIO implements IO {
		private File f;
		private transient InputStream is;
		private transient OutputStream os;
		boolean append = false;

		public FileIO(File f) {
			this.f = f.getAbsoluteFile();
		}

		public FileIO(String path) {
			this(new File(path));
		}

		public InputStream getInputStream() {
			if (f.exists() && f.isFile() && f.canRead()) {
				try { return is = new FileInputStream(f); } catch (Exception ignored) {}
			}
			return null;
		} 

		public OutputStream getOutputStream() {
			Util.mkdirs(f.getParentFile());
			try { 
				f.createNewFile();
				f.setReadable(true, false);
				f.setWritable(true, false);
				os = new FileOutputStream(f, append); 
			} catch (Exception ignored) {}
			return os;
		}

		public void setAppend(boolean append) { 
			this.append = append;
		}

		public void close() {
			try { if (is != null) is.close(); } catch (Exception ignored) {}
			try { if (os != null) os.close(); } catch (Exception ignored) {}
		}

		public String toString() {
			return "FileIO<" + f + ">";
		}
	}

	public static final class MemIO extends ByteArrayOutputStream implements IO {
		public MemIO() { super(0); }
		public InputStream getInputStream() { return new ByteArrayInputStream(buf, 0, count); }
		public OutputStream getOutputStream() { return this; }
		public void setAppend(boolean append) { if (!append) this.reset(); }
		public void close() {} // not needed
		public String toString() { return "MemIO<" + this.hashCode() + ">"; } 
		/**
		 * This is useful when the MemIO was used as the target of --dump-header
		 * @return
		 */
		public Map<String, String> parseDumpedHeader() {
			Map<String, String> result = new LinkedHashMap<String, String>();
			String s = new String(this.toByteArray());
			for (String l: s.split("[\r\n]+")) {
				if (l.trim().length() == 0) continue;
				String[] kv = l.split(":", 2);
				result.put(kv[0], kv.length > 1 ? kv[1].trim() : "");
			}
			return result;
		}
	}

	public static final class CookieStore implements java.net.CookieStore {

		private final ThreadLocal<Map<String, List<HttpCookie>>> cookies = new ThreadLocal<Map<String, List<HttpCookie>>>() {
			@Override protected synchronized Map<String, List<HttpCookie>> initialValue() {
				return new HashMap<String, List<HttpCookie>>();
			}
		};

		private CookieStore() { }

		@Override
		public void add(URI uri, HttpCookie cookie) {
			normalize(uri, cookie);
			Map<String, List<HttpCookie>> map = Util.mapListAdd(cookies.get(), ArrayList.class, cookie.getDomain());
			List<HttpCookie> cc = map.get(cookie.getDomain());
			cc.remove(cookie);
			if (cookie.getMaxAge() != 0) cc.add(cookie);
		}

		@Override
		public List<HttpCookie> get(URI uri) {
			List<HttpCookie> result = getCookies();
			String host = uri.getHost();
			for (ListIterator<HttpCookie> it = result.listIterator(); it.hasNext();) {
				String domain = it.next().getDomain();
				if (!domainMatches(domain, host)) it.remove();
			}
			return result;
		}

		@Override
		public List<HttpCookie> getCookies() {
			List<HttpCookie> result = new ArrayList<HttpCookie>();
			for (List<HttpCookie> cc: cookies.get().values()) {
				for (ListIterator<HttpCookie> it = cc.listIterator(); it.hasNext();)
					if (it.next().hasExpired()) it.remove();
				result.addAll(cc);
			}
			return result;
		}

		@Override
		public List<URI> getURIs() {
			Set<URI> result = new HashSet<URI>();
			for (HttpCookie cookie: getCookies()) {
				String scheme = cookie.getSecure() ? "https" : "http";
				String domain = cookie.getDomain();
				if (domain.startsWith(".")) domain = domain.substring(1);
				try {
					result.add(new URI(scheme, domain, cookie.getPath(), null));
				} catch (URISyntaxException ignored) {}
			}
			return new ArrayList<URI>(result);
		}

		@Override
		public boolean remove(URI uri, HttpCookie cookie) {
			normalize(uri, cookie);
			List<HttpCookie> cc = cookies.get().get(cookie.getDomain());
			return cc != null && cc.remove(cookie);
		}

		@Override
		public boolean removeAll() {
			cookies.get().clear();
			return true;
		}

		private static void normalize(URI uri, HttpCookie cookie) {
			if (cookie.getDomain() == null && uri != null) cookie.setDomain(uri.getHost());
			if (cookie.getPath() == null && uri != null) cookie.setPath(uri.getPath());
			if (Util.empty(cookie.getDomain())) throw new IllegalArgumentException("illegal cookie domain: " + cookie.getDomain());
			if (Util.empty(cookie.getPath())) cookie.setPath("/");
			cookie.setVersion(0);
		}

		/** Check a string domain-matches a given domain string or not. Refer to section 5.1.3 RFC6265 */
		private static boolean domainMatches(String domain, String host) {
			if (domain == null || host == null) return false;
			if (domain.startsWith(".")) { // it's a suffix
				return host.toLowerCase().endsWith(domain.toLowerCase());
			} else {
				return host.equalsIgnoreCase(domain);
			}
		}

	}

	public static final class Recoverable extends Exception {
		private final int httpCode;
		public Recoverable() { this(null, -1); }
		public Recoverable(Throwable cause, int httpCode) { super(cause); this.httpCode = httpCode; }
	}

	final static class Util {

		public static boolean empty(String s) {
			return s == null || s.length() == 0;
		}

		public static <T> List<T> asList(Object o) {
			if (o == null) return new ArrayList<T>(0);
			if (o instanceof Collection) {
				return new ArrayList<T>((Collection<T>) o);
			} else if (o.getClass().isArray()) {
				ArrayList<T> list = new ArrayList<T>();
				for (int i = 0, n = Array.getLength(o); i < n; i++) list.add((T) Array.get(o, i));
				return list;
			} else {
				return listAdd(new ArrayList<T>(1), (T) o);
			}
		}

		public static String qt(Object o) {
			return o == null || o instanceof Boolean || o instanceof Number ?
					"" + o : o instanceof Character ? "'" + o + "'" : "\"" + o + "\"";
		}

		public static String dumpStackTrace(Throwable e, boolean singleLine) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			String s = sw.toString();
			return singleLine ? s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t") : s;
		}

		public static void logStderr(String msg, Object... args) {
			if (args.length > 0) msg = String.format(msg, args);
			System.err.println("[ERR] [" + new Date() + "] " + msg);
		}

		public static <K, V> V mapGet(Map<K, V> map, K key, V fallback) {
			V v;
			return map != null && (v = map.get(key)) != null ? v : fallback;
		}

		public static <K, V> Map<K, List<V>> mapListAdd(Map<K, List<V>> map, K key, V... val) {
			return mapListAdd(map, ArrayList.class, key, val);
		}

		public static <K, V, L extends Collection<V>> Map<K, L> mapListAdd(Map<K, L> map, Class<? extends Collection> collectionClass, K key, V... val) {
			L l;
			if ((l = map.get(key)) == null) try {
				map.put(key, l = (L) collectionClass.newInstance());
			} catch (Exception ignored) { }
			Collections.addAll(l, val);
			return map;
		}

		public static <K, S, V, M extends Map<S, V>> V mapMapGet(Map<K, M> map, K key, S subkey, V fallback) {
			M m;
			V ret;
			return (m = map.get(key)) != null && (ret = m.get(subkey)) != null ? ret : fallback;
		}

		public static <T> Iterable<T> safeIter(Iterable<T> iter) {
			return iter != null ? iter : new ArrayList<T>(0);
		}

		public static <T> T[] safeArray(T[] array, Class<T> componentType) {
			return array != null ? array : (T[]) Array.newInstance(componentType, 0);
		}

		public static Map<String, Object> newMap(Object... keyValuePairs) {
			return mapPut(new LinkedHashMap<String, Object>(), keyValuePairs);
		}

		public static <K, V, M extends Map<K, V>> M mapPut(M map, Object... keyValuePairs) {
			if ((keyValuePairs.length & 1) != 0)
				throw new IllegalArgumentException("the number of keyValuePairs arguments must be odd");
			for (int i = 0, n = keyValuePairs.length; i < n; i += 2) {
				map.put((K) keyValuePairs[i], (V) keyValuePairs[i + 1]);
			}
			return map;
		}

		public static <T, L extends Collection<T>> L listAdd(L list, T... values) {
			list.addAll(Arrays.asList(values));
			return list;
		}

		public static class Ref<T> {
			public int i;
			public T v;

			public Ref(T v) {
				this(0, v);
			}

			public Ref(int i, T v) {
				setInt(i);
				set(v);
			}

			public T get() {
				return v;
			}

			public void set(T v) {
				this.v = v;
			}

			public int getInt() {
				return i;
			}

			public void setInt(int i) {
				this.i = i;
			}

			@Override
			public boolean equals(Object obj) {
				if (!(obj instanceof Ref)) return false;
				Ref<T> o;
				return (o = (Ref<T>) obj) != null && i == o.i && (v == null ? o.v == null : v.equals(o.v));
			}

			@Override
			public int hashCode() {
				return i + (v == null ? 0 : v.hashCode());
			}

			@Override
			public String toString() {
				return String.format("Ref{%s, %s}", i, qt(v));
			}

		}

		public static String urlDecode(String s, String enc) {
			if (!empty(s)) try {
				return URLDecoder.decode(s, enc);
			} catch (Exception ignored) { }
			return s;
		}

		public static String b2s(byte[] bb, String charset, String fallback) {
			return b2s(bb, 0, bb.length, charset, fallback);
		}

		public static String b2s(byte[] bb, int offset, int count, String charset, String fallback) {
			try {
				int start = bb.length - offset >= 3 && bb[offset] == 0xEF && bb[offset + 1] == 0xBB && bb[offset + 2] == 0xBF ? 3 : 0; // deal BOM
				return new String(bb, offset + start, count - start, charset == null ? "UTF-8" : charset);
			} catch (Exception e) {
				return fallback;
			}
		}

		public static byte[] s2b(String s, String charset) {
			try {
				return s.getBytes(charset == null ? "UTF-8" : charset);
			} catch (Exception e) {
				return null;
			}
		}

		public static String[][] split(String s, String delim1, String delim2) {
			String[] ss = s.split(delim1);
			String[][] result = new String[ss.length][];
			for (int i = ss.length; --i >= 0; result[i] = ss[i].split(delim2));
			return result;
		}

		public static Map<String, String> split(String s, String entryDelim, String kvDelim, Map<String, String> toMap) {
			String[] ss = s.split(entryDelim);
			if (toMap == null) toMap = new HashMap<String, String>(ss.length);
			for (String l : ss) {
				String[] sub = l.split(kvDelim);
				toMap.put(sub[0].trim(), sub.length > 1 ? sub[1].trim() : "");
			}
			return toMap;
		}

		public static String join(Object mapOrColl, String delim, String subDelim) {
			List<List<Object>> all = new ArrayList<List<Object>>();
			if (mapOrColl == null) { // do nothing
			} else if (mapOrColl instanceof Map) {
				for (Map.Entry<?, ?> kv : ((Map<?, ?>) mapOrColl).entrySet()) {
					all.add(listAdd(new ArrayList<Object>(2), kv.getKey(), kv.getValue()));
				}
			} else if (mapOrColl instanceof Collection) {
				for (Object o : (Collection<?>) mapOrColl) all.add(asList(o));
			} else if (mapOrColl.getClass().isArray()) {
				for (int i = 0, n = Array.getLength(mapOrColl); i < n; all.add(asList(Array.get(mapOrColl, i++))))
					;
			} else { // plain object
				all.add(asList(mapOrColl));
			}
			StringBuilder sb = new StringBuilder();
			int i = 0, j;
			for (List<Object> sub : all) {
				if (i++ > 0) sb.append(delim);
				j = 0;
				for (Object o : sub) sb.append(j++ > 0 ? subDelim : "").append(o);
			}
			return sb.toString();
		}

		public static String base64Encode(byte[] bb) {
			Class<?> clz = getClass("java.util.Base64", null);
			if (clz != null) {
				Object encoder = invokeSilent(null, clz, "getEncoder", false, null);
				return (String) invokeSilent(encoder, null, "encodeToString", false, "[B", (Object) bb);
			}
			clz = getClass("sun.misc.BASE64Encoder", null);
			if (clz != null) {
				Object encoder = createInstance(clz, "", true);
				return ((String) invokeSilent(encoder, null, "encode", true, "[B", (Object) bb)).replaceAll("[\r\n]+", "");
			}
			clz = getClass("org.apache.commons.codec.binary.Base64", null);
			if (clz != null) {
				return (String) invokeSilent(null, clz, "encodeBase64String", false, "[B", (Object) bb);
			}
			clz = getClass("android.util.Base64", null);
			if (clz != null) {
				return (String) invokeSilent(null, clz, "encodeToString", false, "[BI", bb, 2); // NO_WRAP
			}
			throw new RuntimeException(new NoSuchMethodException("base64Encode"));
		}

		public static byte[] readStream(InputStream is, boolean close) {
			return readStream(is, 0, close);
		}

		public static byte[] readStream(InputStream is, int interruptOnSize, boolean close) {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			int count = 0, c;
			while ((c = pipeStream(is, bos)) > 0 && (interruptOnSize <= 0 || count < interruptOnSize)) count += c;
			if (c < 0) count += (c & PIPE_COUNT_MASK);
			byte[] result = c < 0 && count == 0 ? null : bos.toByteArray();
			if (close) try {
				is.close();
			} catch (Exception ignored) {
			}
			return result;
		}

		public static final int PIPE_COUNT_MASK = 0x7FFFFFFF;

		private static final int BUFFER_SIZE = 10000;

		public static int pipeStream(InputStream source, OutputStream destination) {
			byte[] bb = new byte[BUFFER_SIZE];
			int len, count = 0;
			do {
				len = 0;
				try {
					len = source.read(bb);
				} catch (SocketTimeoutException e) { // no data, but the socket connection is still alive
				} catch (SocketException e) { // EOF or socket disconnected
					len = -1;
				} catch (IOException e) { // unexpected exceptions
					throw new RuntimeException(e);
				}
				if (len > 0) {
					try {
						destination.write(bb, 0, len);
					} catch (IOException e) { // unexpected exceptions while writing
						throw new RuntimeException(e);
					}
					count += len;
				}
			} while (len == BUFFER_SIZE);
			return len < 0 ? (0x80000000 | count) : count; // len < 0 -> EOF reached
		}

		public static void mkdirs(File dir) {
			File parent = dir.getAbsoluteFile();
			List<File> mkdir = new ArrayList<File>();
			for (; !parent.exists() || !parent.isDirectory(); parent = parent.getParentFile()) {
				mkdir.add(parent);
			}
			for (int i = mkdir.size(); --i >= 0; ) {
				File d = mkdir.get(i);
				d.mkdir();
				d.setReadable(true, false);
				d.setWritable(true, false);
			}
		}

		public static Class<?> getClass(String className, ClassLoader cl) {
			try {
				return (cl != null ? cl : CUrl.class.getClassLoader()).loadClass(className);
			} catch (ClassNotFoundException e) {
				return null;
			}
		}

		public static <T> T createInstance(Class<T> cls, String signature, boolean ignoreAccess, Object... args) {
			if (signature == null && args.length == 0) {
				try {
					return cls.newInstance();
				} catch (Exception ex) {
					throw new IllegalArgumentException(ex);
				}
			}
			return (T) invoke(null, cls, "<init>", ignoreAccess, signature, args);
		}

		public static Object getField(Object thiz, Class<?> cls, String fieldName, Object fallback, boolean ignoreAccess) {
			if (thiz == null && cls == null || fieldName == null)
				throw new NullPointerException("inst=" + thiz + ",class=" + cls + ",field=" + fieldName);
			try {
				for (MemberInfo mi : safeIter(getMembers(thiz != null ? thiz.getClass() : cls, fieldName))) {
					if (-1 == mi.numArgs && (ignoreAccess || (mi.member.getModifiers() & Modifier.PUBLIC) != 0)) {
						AccessibleObject acc;
						if (ignoreAccess && !(acc = (AccessibleObject) mi.member).isAccessible()) acc.setAccessible(true);
						return ((Field) mi.member).get(thiz);
					}
				}
			} catch (Exception ignored) {
			}
			return fallback;
		}

		public static Object invokeSilent(Object thiz, Class<?> cls, String methodName, boolean ignoreAccess, String signature, Object... args) {
			try {
				return invoke(thiz, cls, methodName, ignoreAccess, signature, args);
			} catch (Exception ignored) {
			}
			return null;
		}

		public static Object invoke(Object thiz, Class<?> cls, String methodName, boolean ignoreAccess, String signature, Object... args) {
			if (thiz == null && cls == null || methodName == null)
				throw new NullPointerException("inst=" + thiz + ",class=" + cls + ",method=" + methodName);
			List<MemberInfo> found = getMembers(thiz != null ? thiz.getClass() : cls, methodName);
			try {
				Member m = null;
				if (found == null) { // do nothing
				} else if (signature == null) {
					int len = args.length;
					for (MemberInfo mi : found) {
						if (len == mi.numArgs && (ignoreAccess || (mi.member.getModifiers() & Modifier.PUBLIC) != 0)) {
							m = mi.member;
							break;
						}
					}
				} else {
					signature = signature.replace('/', '.');
					for (MemberInfo mi : found) {
						if (signature.equals(mi.signature) && (ignoreAccess || (mi.member.getModifiers() & Modifier.PUBLIC) != 0)) {
							m = mi.member;
							break;
						}
					}
				}
				if (m == null) {
					StringBuilder msg = new StringBuilder().append('"').append(methodName).append('"');
					if (signature == null) {
						msg.append(" with ").append(args.length).append(" parameter(s)");
					} else {
						msg.append(" with signature \"").append(signature).append("\"");
					}
					throw new NoSuchMethodException(msg.toString());
				}
				AccessibleObject acc;
				if (ignoreAccess && !(acc = (AccessibleObject) m).isAccessible()) acc.setAccessible(true);
				return m instanceof Method ? ((Method) m).invoke(thiz, args) : ((Constructor<?>) m).newInstance(args);
			} catch (Exception ex) {
				throw new IllegalArgumentException(ex);
			}
		}

		private static final Map<String, Object> primaryTypes = newMap(
				byte.class, 'B',
				char.class, 'C',
				double.class, 'D',
				float.class, 'F',
				int.class, 'I',
				long.class, 'J',
				short.class, 'S',
				void.class, 'V',
				boolean.class, 'Z');

		@SuppressWarnings("unlikely-arg-type")
		public static String getSignature(Class<?>... types) {
			StringBuilder sb = new StringBuilder();
			for (Class<?> t : types) {
				while (t.isArray()) {
					sb.append('[');
					t = t.getComponentType();
				}
				Character c;
				if ((c = (Character) primaryTypes.get(t)) != null) {
					sb.append(c);
				} else {
					sb.append('L').append(t.getName()).append(';');
				}
			}
			return sb.toString();
		}

		private static final Map<Class<?>, Map<String, List<MemberInfo>>> mapClassMembers = new HashMap<Class<?>, Map<String, List<MemberInfo>>>();

		private static synchronized List<MemberInfo> getMembers(Class<?> cls, String name) {
			if (!mapClassMembers.containsKey(cls)) {
				Map<String, List<MemberInfo>> map;
				mapClassMembers.put(cls, map = new LinkedHashMap<String, List<MemberInfo>>());
				Class<?> clss = cls;
				while (clss != null && !Object.class.equals(clss)) {
					for (Constructor<?> c : safeArray(clss.getDeclaredConstructors(), Constructor.class)) {
						Class<?>[] ptypes = c.getParameterTypes();
						mapListAdd(map, "<init>", new MemberInfo(getSignature(ptypes), ptypes.length, c));
					}
					for (Method m : safeArray(clss.getDeclaredMethods(), Method.class)) {
						Class<?>[] ptypes = m.getParameterTypes();
						mapListAdd(map, m.getName(), new MemberInfo(getSignature(ptypes), ptypes.length, m));
					}
					for (Field f : safeArray(clss.getDeclaredFields(), Field.class)) {
						mapListAdd(map, f.getName(), new MemberInfo(null, -1, f));
					}
					clss = clss.getSuperclass();
				}
			}
			return mapMapGet(mapClassMembers, cls, name, null);
		}

		private static class MemberInfo {
			String signature; // null for field
			int numArgs; // -1 for field
			Member member;

			MemberInfo(String sign, int num, Member member) {
				signature = sign;
				numArgs = num;
				this.member = member;
			}

			public final String toString() {
				return member.toString();
			}
		}

	}

	public static void main(String[] args) {
		System.out.println(new CUrl().opt(args).exec(null));
	}

}
