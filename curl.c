#include <curl/curl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define _GNU_SOURCE
#include <getopt.h>

/* When certificate doesn't work, we get this...

HTTP/1.1 200 OK
Server: Virata-EmWeb/R6_2_0
Transfer-Encoding: chunked
Content-Type: text/xml
Cache-Control: max-age=0
Set-Cookie: webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/
Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/
Set-Cookie: webvpnlogin=1
Set-Cookie: ClientCertAuthFailed=1; path=/
X-Transcend-Version: 1

<?xml version="1.0" encoding="UTF-8"?>
<auth id="main">
<title>SSL VPN Service</title>
<ca status="disabled" href="/+CSCOCA+/login.html" />



<banner></banner>
<message>Please enter your username and password.</message>
<form method="post" action="/+webvpn+/index.html">
<input type="text" name="username" label="USERNAME:" />
<input type="password" name="password" label="Password:" />
<select name="group_list" label="GROUP:">
<option noaaa="0" value="Layer3">Certificate</option>
<option noaaa="0" value="Layer3_ACE" auth-type="sdi-via-proxy" override-name="password" override-label="PASSCODE:">SecureID</option>
</select><input type="submit" name="Login" value="Login" />
<input type="reset" name="Clear" value="Clear" />


</form>
</auth>


When it _does_ work, we get this:

HTTP/1.1 200 OK
Server: Virata-EmWeb/R6_2_0
Transfer-Encoding: chunked
Content-Type: text/xml
Cache-Control: max-age=0
Set-Cookie: webvpnlogin=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/
Set-Cookie: tg=1Layer3; expires=Mon, 22 Sep 2008 11:36:46 GMT; path=/
Set-Cookie: webvpn=3581410512@1417216@1222033006@E13E470F73AE0BE3B35489C81C2EC8DD6B85CE20;PATH=/
Set-Cookie: webvpnc=bu:/CACHE/stc/&p:t&iu:1/&ch:37C73A3479D303724341163E6AF59A47737FFFA0&sh:E4B3B401B7C2F3F6FC628033C84BAD14BB184312&lu:/+CSCOT+/translation-table?textdomain%3DAnyConnect%26type%3Dmanifest&fu:profiles/OrionAnyConnect.xml&fh:85DA4F255850F68167BBCABBB4F33A1D25EA66A3;PATH=/
X-Transcend-Version: 1

<?xml version="1.0" encoding="UTF-8"?>
<auth id="success">
<title>SSL VPN Service</title>
<message>Success</message>
<success/>
</auth>


The fh: is a sha1sum of the xml profile file, while its URL is bu: followed by
fu: -- in the above case, /CACHE/stc/profiles/OrionAnyConnect.xml


Sometimes when we give it a good SecurID passcode, we get this... 

HTTP/1.1 200 OK
Server: Virata-EmWeb/R6_2_0
Transfer-Encoding: chunked
Content-Type: text/xml
Cache-Control: max-age=0
Set-Cookie: tg=1Layer3_ACE; expires=Thu, 25 Sep 2008 12:18:17 GMT; path=/
X-Transcend-Version: 1

<?xml version="1.0" encoding="UTF-8"?>
<auth id="next_tokencode">
<title>SSL VPN Service</title>

<message id="54" param1="" param2="">Enter the next card code to complete authentication.</message>

<form method="post" action="/+webvpn+/login/challenge.html">
<input type="password" name="password" label="Token Code:" />

<input type="submit" name="Continue" value="Continue" />
<input type="submit" name="Cancel" value="Cancel" />

<input type="hidden" name="auth_handle" value="1692" />
<input type="hidden" name="status" value="2" />
<input type="hidden" name="username" value="dwoodhou" />
<input type="hidden" name="challenge_code" value="10" />
</form>
</auth>






*/

static int verbose = 0;
static int dump = 0;

struct response_buf {
	size_t size;
	char *buf;
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb,
						struct response_buf *resp)
{
	size_t this_size = (size * nmemb);

	resp->buf = realloc(resp->buf, resp->size + this_size + 1);
	memcpy(resp->buf + resp->size, ptr, this_size);
	resp->size += this_size;
	resp->buf[resp->size] = 0;

	return this_size;
}

static int get_cookie(CURL *curl)
{
	struct curl_slist *cookies, *thiscookie;

	/* Double-check that we have a webvpn cookie */
	curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);

	for (thiscookie = cookies; thiscookie; thiscookie = thiscookie->next) {
		char *field = thiscookie->data;

		if (!(field = strchr(field, '\t')) ||
				!(field = strchr(field + 1, '\t')) ||
				!(field = strchr(field + 1, '\t')) ||
				!(field = strchr(field + 1, '\t')) ||
				!(field = strchr(field + 1, '\t')) ||
					strncmp(field + 1, "webvpn\t", 7))
			continue;

		field += 8;
		if (!strlen(field)) {
			fprintf(stderr, "Cookie field is empty\n");
			return -EINVAL;
		}

		printf("WebVPN cookie is %s\n", field);
		//cookie = strdup(field);
	}

	curl_slist_free_all(cookies);

	return 0;
}

static int parse_response(CURL *curl, char *hostname,
					char *username, char *password,
						struct response_buf *resp);

static int parse_form(CURL *curl, xmlNode *xml_node, char *hostname,
				char *action, char *username, char *password)
{
	struct response_buf resp = { 0, NULL };
	char curl_err[CURL_ERROR_SIZE];
	char url_buf[1024], post_buf[1024];
	long respcode;

	printf("Hostname %s%s, username %s\n", hostname, action, username);

	memset(url_buf, 0, sizeof(url_buf));
	snprintf(url_buf, sizeof(url_buf) - 1, "https://%s%s",
							hostname, action);

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp(xml_node->name, "input") ||
					!strcmp(xml_node->name, "select")) {
			char *name, *label;
			name = xmlGetProp(xml_node, "name");
			label = xmlGetProp(xml_node, "label");
			if (verbose)
				printf("%s %s\n", name, label);
		}
	}

	memset(post_buf, 0, sizeof(post_buf));
	snprintf(post_buf, sizeof(post_buf) - 1,
			"group_list=Layer3_ACE&username=%s&password=%s",
							username, password);

	curl_easy_setopt(curl, CURLOPT_URL, url_buf);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_buf));

	if (curl_easy_perform(curl)) {
		fprintf(stderr, "Curl error: %s\n", curl_err);
		return -EINVAL;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respcode);

	if (respcode != 200) {
		fprintf(stderr, "Curl fetch failed, response code %d\n",
								respcode);
		if (verbose) {
			fprintf(stderr, "Response was:\n");
			fprintf(stderr, resp.buf);
		}
		return -EINVAL;
	}

	if (dump)
		printf("%s\n", resp.buf);

	if (parse_response(curl, hostname, username, password, &resp) < 0)
		return -EINVAL;

	free(resp.buf);

	return 0;
}

static int parse_response(CURL *curl, char *hostname,
					char *username, char *password,
						struct response_buf *resp)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	char *page;

	xml_doc = xmlReadMemory(resp->buf, resp->size, "noname.xml", NULL, 0);

	if (!xml_doc) {
		fprintf(stderr, "Failed to parse XML response\n");
		if (verbose) {
			fprintf(stderr, "Response was:\n");
			fprintf(stderr, resp->buf);
		}
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (xml_node->type != XML_ELEMENT_NODE ||
					strcmp(xml_node->name, "auth")) {
		fprintf(stderr, "XML response has no \"auth\" root node\n");
		xmlFreeDoc(xml_doc);
		return -EINVAL;
	}

	page = xmlGetProp(xml_node, "id");
	if (verbose)
		printf("Page is %s\n", page);

	if (!strcmp(page, "success"))
		return 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp(xml_node->name, "message"))
			printf("%s\n", xmlNodeGetContent(xml_node));
		else if (!strcmp(xml_node->name, "error")) {
			printf("%s\n", xmlNodeGetContent(xml_node));
			return -EINVAL;
		} else if (!strcmp(xml_node->name, "form")) {
			char *method, *action;
			method = xmlGetProp(xml_node, "method");
			action = xmlGetProp(xml_node, "action");
			if (verbose)
				printf("%s %s\n", method, action);
			parse_form(curl, xml_node, hostname, action,
							username, password);
		}
	}

	xmlFreeDoc(xml_doc);

	return 0;
}

static int connect_ssl(char *hostname, char *cert,
					char *username, char *password)
{
	CURL *curl;
	char curl_err[CURL_ERROR_SIZE];
	char url_buf[1024];
	long respcode;
	struct curl_slist *headers;
	struct response_buf resp = { 0, NULL };

	printf("Hostname %s, cert %s\n", hostname, cert);

	if (curl_global_init(CURL_GLOBAL_SSL)) {
		fprintf(stderr, "Curl initialisation failed\n");
		exit(1);
	}

	curl = curl_easy_init();

	memset(url_buf, 0, sizeof(url_buf));
	snprintf(url_buf, sizeof(url_buf) - 1, "https://%s/", hostname);

	curl_easy_setopt(curl, CURLOPT_URL, url_buf);
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

	/* FIXME: We'll want to teach cURL about using the TPM for this */
	if (cert)
		curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);

	headers = curl_slist_append(NULL, "X-Transcend-Version: 1");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

	if (curl_easy_perform(curl)) {
		fprintf(stderr, "Curl error: %s\n", curl_err);
		curl_easy_cleanup(curl);
		return -EINVAL;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respcode);

	if (respcode != 200) {
		fprintf(stderr, "Curl fetch failed, response code %d\n",
								respcode);
		if (verbose) {
			fprintf(stderr, "Response was:\n");
			fprintf(stderr, resp.buf);
		}
		curl_easy_cleanup(curl);
		return -EINVAL;
	}

	if (dump)
		printf("%s\n", resp.buf);

	if (parse_response(curl, hostname, username, password, &resp) < 0) {
		curl_easy_cleanup(curl);
		return -EINVAL;
	}

	free(resp.buf);

	get_cookie(curl);

	curl_easy_cleanup(curl);

	return 0;
}

static struct option long_options[] = {
	{ "certificate", 1, 0, 'c'},
	{ "username", 1, 0, 'u' },
	{ "password", 1, 0, 'p' },
	{ "verbose", 1, 0, 'v'},
};

static void usage(void)
{
	printf("Usage:  getwebvpn [options] <server>\n");
	printf("Get webvpn cookie from server.\n\n");
	printf("  -c, --certificate=CERT     Use SSL client certificate CERT\n");
	printf("  -u, --username=USER        Username for authenticate\n");
	printf("  -p, --password=PASS        Password for authenticate\n");
	printf("  -v, --verbose              More output\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *cert = NULL, *username = NULL, *password = NULL;
	int opt;

	while ((opt = getopt_long(argc, argv, "c:u:p:vh",
				  long_options, NULL))) {
		if (opt < 0)
			break;

		switch (opt) {
		case 'c':
			cert = optarg;
			break;
		case 'u':
			username = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
		}
	}
	if (optind != argc - 1) {
		fprintf(stderr, "No server specified\n");
		usage();
	}

	if (!cert && (!username || !password)) {
		fprintf(stderr, "Either cert or user/pass must be specified\n");
		usage();
	}

	LIBXML_TEST_VERSION;

	return connect_ssl(argv[optind], cert, username, password);
}
