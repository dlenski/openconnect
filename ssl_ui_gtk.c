/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
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

typedef struct dialog_data {
	GtkWidget *dlg;
	GtkWidget *vbox;
}dialog_data;

static int ui_open(UI *ui)
{
	GtkWidget *dlg;
	GtkWidget *box;
	dialog_data *data;

	dlg = gtk_dialog_new_with_buttons("Connect to VPN", NULL, GTK_DIALOG_MODAL,
					  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					  GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
					  NULL);
	box = gtk_vbox_new (FALSE, 4);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), box, FALSE, FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER(box),8);
	gtk_widget_show (box);

	data = g_slice_new(dialog_data);
	data->dlg = dlg;
	data->vbox = box;

	UI_add_user_data(ui, data);
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
        gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	GtkWidget *hbox, *text, *entry;
	dialog_data *data;

	data = UI_get0_user_data(ui);


	switch (UI_get_string_type(uis)) {
	case UIT_ERROR:
	case UIT_INFO:
		text = gtk_label_new(UI_get0_output_string(uis));
		gtk_box_pack_start(GTK_BOX(data->vbox), text, FALSE, FALSE, 0);
		gtk_widget_show(text);
		break;

	case UIT_BOOLEAN:
		/* FIXME */
		break;

	case UIT_PROMPT:
	case UIT_VERIFY:
		hbox = gtk_hbox_new(FALSE, 0);
		gtk_box_pack_start(GTK_BOX(data->vbox), hbox, FALSE, FALSE, 0);
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
		g_signal_connect(G_OBJECT(entry), "activate", G_CALLBACK(entry_activate_cb), data->dlg);
		gtk_widget_show(entry);
		break;

	case UIT_NONE:
		;
	}
	return 1;
}

static int ui_close(UI *ui)
{
	dialog_data *data;

	data = UI_get0_user_data(ui);

	gtk_widget_destroy(data->dlg);
	g_slice_free(dialog_data, data);
	gdk_flush();

	return 1;
}

static int ui_flush(UI* ui)
{
	dialog_data *data;
	int response;

	data = UI_get0_user_data(ui);

	response = gtk_dialog_run(GTK_DIALOG(data->dlg));

	/* -1 = cancel,
	 *  0 = failure,
	 *  1 = success */
	return (response == GTK_RESPONSE_ACCEPT ? 1 : -1);
}

int set_openssl_ui(void)
{
	UI_METHOD *ui_method = UI_create_method("OpenConnect VPN UI (gtk)");

	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_flusher(ui_method, ui_flush);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_closer(ui_method, ui_close);

	UI_set_default_method(ui_method);
	return 0;
}

