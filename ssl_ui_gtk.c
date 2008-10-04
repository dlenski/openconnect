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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>

#include <openssl/ssl.h>
#include <openssl/ui.h>

static UI *ssl_ui;

static int ui_open(UI *ui)
{
	GtkWidget *dlg;

	dlg = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_QUESTION,
				     GTK_BUTTONS_OK_CANCEL, "OpenConnect");
	gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_OK);
	

	UI_add_user_data(ui, dlg);
	ssl_ui = ui;
	return 1;
}

static void entry_changed_cb(GtkWidget *widget, gpointer user_data)
{
	UI_set_result(ssl_ui, user_data, gtk_entry_get_text(GTK_ENTRY(widget)));
}

static void entry_activate_cb(GtkWidget *widget, gpointer dlg)
{
        g_return_if_fail(GTK_IS_DIALOG(dlg));
        gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_OK);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	GtkWidget *dlg = UI_get0_user_data(ui);
	GtkWidget *hbox, *text, *entry;

	switch (UI_get_string_type(uis)) {
	case UIT_ERROR:
	case UIT_INFO:
		text = gtk_label_new(UI_get0_output_string(uis));
		gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), text, FALSE, FALSE, 0);
		gtk_widget_show(text);
		break;

	case UIT_BOOLEAN:
		/* FIXME */
		break;

	case UIT_PROMPT:
	case UIT_VERIFY:
		hbox = gtk_hbox_new(FALSE, 0);
		gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), hbox, FALSE, FALSE, 0);
		gtk_widget_show(hbox);

		text = gtk_label_new(UI_get0_output_string(uis));
		gtk_box_pack_start(GTK_BOX(hbox), text, FALSE, FALSE, 0);
		gtk_widget_show(text);

		entry = gtk_entry_new();
		gtk_box_pack_end(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
		//gtk_entry_set_width_chars(GTK_ENTRY(entry), 20);
		if (!(UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO))
			gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		g_signal_connect(G_OBJECT(entry), "changed", G_CALLBACK(entry_changed_cb), uis);
		g_signal_connect(G_OBJECT(entry), "activate", G_CALLBACK(entry_activate_cb), dlg);
		gtk_widget_show(entry);
		break;

	case UIT_NONE:
		;
	}
	return 1;
}

static int ui_close(UI *ui)
{
	GtkWidget *dlg = UI_get0_user_data(ui);

	gtk_widget_destroy(dlg);
	return 1;
}

static int ui_flush(UI* ui)
{
	GtkWidget *dlg = UI_get0_user_data(ui);

	int response = gtk_dialog_run(GTK_DIALOG(dlg));
	return response == GTK_RESPONSE_OK;
}

int set_openssl_ui(void)
{
	UI_METHOD *ui_method = UI_create_method("OpenConnect VPN UI (gtk)");

	gtk_init(0,  NULL);

	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_flusher(ui_method, ui_flush);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_closer(ui_method, ui_close);

	UI_set_default_method(ui_method);
	return 0;
}

