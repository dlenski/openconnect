#include <curl/curl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

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




*/

int verbose = 1;
struct response_buf {
	size_t size;
	char *buf;
};

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, struct response_buf *resp)
{
	size_t this_size = (size * nmemb);

	resp->buf = realloc(resp->buf, resp->size + this_size + 1);
	memcpy(resp->buf + resp->size, ptr, this_size);
	resp->size += this_size;
	resp->buf[resp->size] = 0;

       	return this_size;
}

static void
print_element_names(xmlNode * a_node, int depth)
{
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
		char *prop;
		printf("depth: %d, node type: Element, name: %s\n", depth, cur_node->name);
		prop = xmlGetProp(cur_node, "id");
		if (prop)
			printf("id = %s\n", prop);
        }

	print_element_names(cur_node->children, depth + 1);
    }
}



int connect_ssl(char *hostname, char *cert)
{
	CURL *curl;
	char curl_err[CURL_ERROR_SIZE];
	long respcode;
	char url_buf[1024];
	struct curl_slist *headers;
	struct curl_slist *cookies, *thiscookie;
	struct response_buf resp = { 0, NULL };
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	char *xml_message = NULL;
	int xml_success = 0;

	printf("Hostname %s, cert %s\n", hostname, cert);
	
	LIBXML_TEST_VERSION;
	if (curl_global_init(CURL_GLOBAL_SSL)) {
		fprintf(stderr, "Curl initialisation failed\n");
		exit(1);
	}

	curl = curl_easy_init();
	
	url_buf[1023] = 0;
	snprintf(url_buf, 1023, "https://%s/", hostname);

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
		curl = NULL;
		return -EINVAL;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respcode);

	if (respcode != 200) {
		fprintf(stderr, "Curl fetch failed, response code %d\n", respcode);
		goto dump_response;
	}

	xml_doc = xmlReadMemory(resp.buf, resp.size, "noname.xml", NULL, 0);
	free(resp.buf);
	if (!xml_doc) {
		fprintf(stderr, "Failed to parse XML response\n");
	dump_response:
		if (verbose) {
			fprintf(stderr, "Response was:\n");
			fprintf(stderr, resp.buf);
		}
		curl_easy_cleanup(curl);
		curl = NULL;
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	
	if (xml_node->type != XML_ELEMENT_NODE ||
	    strcmp(xml_node->name, "auth")) {
		fprintf(stderr, "XML response didn't have \"auth\" as root node\n");
		xmlFreeDoc(xml_doc);
		curl_easy_cleanup(curl);
		curl = NULL;
		return -EINVAL;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type == XML_ELEMENT_NODE) {
			if (!strcmp(xml_node->name, "message"))
				xml_message = xmlNodeGetContent(xml_node);
			else if (!strcmp(xml_node->name, "success"))
				xml_success = 1;
		}
	}

	xmlFreeDoc(xml_doc);

	if (!xml_success) {
		fprintf(stderr, "Server returned unsuccessful\nServer message: %s\n",
			xml_message);

		/* FIXME: Handle the form (shown above), and try again. */

		curl_easy_cleanup(curl);
		curl = NULL;
		return -EINVAL;
	};

	/* Double-check that we have a webvpn cookie */
	curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);

	for (thiscookie = cookies; thiscookie; thiscookie = thiscookie->next) {
		char *field = thiscookie->data;

		if (!(field = strchr(field, '\t')) ||
		    !(field = strchr(field+1, '\t')) ||
		    !(field = strchr(field+1, '\t')) ||
		    !(field = strchr(field+1, '\t')) ||
		    !(field = strchr(field+1, '\t')) ||
		    strncmp(field+1, "webvpn\t", 7))
			continue;

		field += 8;
		if (!strlen(field)) {
			fprintf(stderr, "Cookie field is empty\n");
			curl_easy_cleanup(curl);
			curl = NULL;
			return -EINVAL;
		}

		printf("WebVPN cookie is %s\n", field);
		//cookie = strdup(field);
	}

	curl_slist_free_all(cookies);

	return 0;

}

int main(int argc, char **argv)
{
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s <host> [<cert.pem>]\n", argv[0]);
		exit(1);
	}

	return connect_ssl(argv[1], (argc==3)?argv[2]:NULL);
}
