/*
 * Open AnyConnect (SSL + DTLS) client
 *
 * © 2008 David Woodhouse <dwmw2@infradead.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */
#include <openssl/ssl.h>
#include <openssl/ui.h>

/* OpenSSL UI method calls. These are just stubs, to show how it's done */
/* While we can set user data on the calls from the TPM setup, we can't
   set it on the calls for PEM certificate passphrases, AFAICT. */
static int ui_open(UI *ui)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}
static int ui_write(UI *ui, UI_STRING *uis)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);

}
static int ui_close(UI *ui)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_closer(UI_OpenSSL())(ui);
}

int set_openssl_ui(void)
{
	UI_METHOD *ui_method = UI_create_method("AnyConnect VPN UI");

	/* Set up a UI method of our own for password/passphrase requests */
	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_reader(ui_method, ui_read);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_closer(ui_method, ui_close);

	UI_set_default_method(ui_method);

	return 0;
}

