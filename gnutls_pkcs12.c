/*
 * Ick. This is (or at least started off as) a straight copy of
 * parse_pkcs12() from GnuTLS lib/gnutls_x509.c, as of commit ID
 * 77670476814c078bbad56ce8772b192a3b5736b6 on the gnutls_2_12_x
 * branch.
 *
 * We need to *see* the cert so that we can check its expiry, and
 * we'll also want to get all the other certs in the PKCS#12 file
 * rather than only the leaf node. Hopefully these changes can be
 * merged back into GnuTLS as soon as possible, it can be made a
 * public function, and this copy can die.
 */
#define opaque unsigned char
#define gnutls_assert() do {} while(0)

/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 * Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file WAS part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */


static int
parse_pkcs12 (gnutls_certificate_credentials_t res,
              gnutls_pkcs12_t p12,
              const char *password,
              gnutls_x509_privkey_t * key,
              gnutls_x509_crt_t * cert,
              gnutls_x509_crt_t ** extra_certs_ret,
              unsigned int * extra_certs_ret_len,
              gnutls_x509_crl_t * crl)
{
  gnutls_pkcs12_bag_t bag = NULL;
  gnutls_x509_crt_t *extra_certs = NULL;
  int extra_certs_len = 0;
  int idx = 0;
  int ret;
  size_t cert_id_size = 0;
  size_t key_id_size = 0;
  opaque cert_id[20];
  opaque key_id[20];
  int privkey_ok = 0;

  *cert = NULL;
  *key = NULL;
  *crl = NULL;

  /* find the first private key */
  for (;;)
    {
      int elements_in_bag;
      int i;

      ret = gnutls_pkcs12_bag_init (&bag);
      if (ret < 0)
        {
          bag = NULL;
          gnutls_assert ();
          goto done;
        }

      ret = gnutls_pkcs12_get_bag (p12, idx, bag);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
        break;
      if (ret < 0)
        {
          gnutls_assert ();
          goto done;
        }

      ret = gnutls_pkcs12_bag_get_type (bag, 0);
      if (ret < 0)
        {
          gnutls_assert ();
          goto done;
        }

      if (ret == GNUTLS_BAG_ENCRYPTED)
        {
          ret = gnutls_pkcs12_bag_decrypt (bag, password);
          if (ret < 0)
            {
              gnutls_assert ();
              goto done;
            }
        }

      elements_in_bag = gnutls_pkcs12_bag_get_count (bag);
      if (elements_in_bag < 0)
        {
          gnutls_assert ();
          goto done;
        }

      for (i = 0; i < elements_in_bag; i++)
        {
          int type;
          gnutls_datum_t data;

          type = gnutls_pkcs12_bag_get_type (bag, i);
          if (type < 0)
            {
              gnutls_assert ();
              goto done;
            }

          ret = gnutls_pkcs12_bag_get_data (bag, i, &data);
          if (ret < 0)
            {
              gnutls_assert ();
              goto done;
            }

          switch (type)
            {
            case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
            case GNUTLS_BAG_PKCS8_KEY:
              if (*key != NULL) /* too simple to continue */
                {
                  gnutls_assert ();
                  break;
                }

              ret = gnutls_x509_privkey_init (key);
              if (ret < 0)
                {
                  gnutls_assert ();
                  goto done;
                }

              ret = gnutls_x509_privkey_import_pkcs8
                (*key, &data, GNUTLS_X509_FMT_DER, password,
                 type == GNUTLS_BAG_PKCS8_KEY ? GNUTLS_PKCS_PLAIN : 0);
              if (ret < 0)
                {
                  gnutls_assert ();
                  gnutls_x509_privkey_deinit (*key);
                  goto done;
                }

              key_id_size = sizeof (key_id);
              ret =
                gnutls_x509_privkey_get_key_id (*key, 0, key_id,
                                                &key_id_size);
              if (ret < 0)
                {
                  gnutls_assert ();
                  gnutls_x509_privkey_deinit (*key);
                  goto done;
                }

              privkey_ok = 1;   /* break */
              break;
            default:
              break;
            }
        }

      idx++;
      gnutls_pkcs12_bag_deinit (bag);

      if (privkey_ok != 0)      /* private key was found */
        break;
    }

  if (privkey_ok == 0)          /* no private key */
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  /* now find the corresponding certificate 
   */
  idx = 0;
  bag = NULL;
  for (;;)
    {
      int elements_in_bag;
      int i;

      ret = gnutls_pkcs12_bag_init (&bag);
      if (ret < 0)
        {
          bag = NULL;
          gnutls_assert ();
          goto done;
        }

      ret = gnutls_pkcs12_get_bag (p12, idx, bag);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
        break;
      if (ret < 0)
        {
          gnutls_assert ();
          goto done;
        }

      ret = gnutls_pkcs12_bag_get_type (bag, 0);
      if (ret < 0)
        {
          gnutls_assert ();
          goto done;
        }

      if (ret == GNUTLS_BAG_ENCRYPTED)
        {
          ret = gnutls_pkcs12_bag_decrypt (bag, password);
          if (ret < 0)
            {
              gnutls_assert ();
              goto done;
            }
        }

      elements_in_bag = gnutls_pkcs12_bag_get_count (bag);
      if (elements_in_bag < 0)
        {
          gnutls_assert ();
          goto done;
        }

      for (i = 0; i < elements_in_bag; i++)
        {
          int type;
          gnutls_datum_t data;
          gnutls_x509_crt_t this_cert;

          type = gnutls_pkcs12_bag_get_type (bag, i);
          if (type < 0)
            {
              gnutls_assert ();
              goto done;
            }

          ret = gnutls_pkcs12_bag_get_data (bag, i, &data);
          if (ret < 0)
            {
              gnutls_assert ();
              goto done;
            }

          switch (type)
            {
            case GNUTLS_BAG_CERTIFICATE:
              ret = gnutls_x509_crt_init (&this_cert);
              if (ret < 0)
                {
                  gnutls_assert ();
                  goto done;
                }

              ret =
                gnutls_x509_crt_import (this_cert, &data, GNUTLS_X509_FMT_DER);
              if (ret < 0)
                {
                  gnutls_assert ();
                  gnutls_x509_crt_deinit (this_cert);
                  goto done;
                }

              /* check if the key id match */
              cert_id_size = sizeof (cert_id);
              ret =
                gnutls_x509_crt_get_key_id (this_cert, 0, cert_id, &cert_id_size);
              if (ret < 0)
                {
                  gnutls_assert ();
                  gnutls_x509_crt_deinit (this_cert);
                  goto done;
                }

              if (memcmp (cert_id, key_id, cert_id_size) != 0)
                {               /* they don't match - skip the certificate */
                  if (extra_certs_ret)
                    {
                      extra_certs = gnutls_realloc (extra_certs,
                                                    sizeof(extra_certs[0]) *
                                                    ++extra_certs_len);
                      if (!extra_certs)
                        {
                          gnutls_assert ();
                          ret = GNUTLS_E_MEMORY_ERROR;
                          goto done;
                        }
                      extra_certs[extra_certs_len - 1] = this_cert;
                      this_cert = NULL;
                    }
                  else
                    {
                       gnutls_x509_crt_deinit (this_cert);
                    }
                  break;
                }
              else
                {
                   if (*cert != NULL)        /* no need to set it again */
                     {
                        gnutls_assert ();
                        break;
                     }
                   *cert = this_cert;
                   this_cert = NULL;
                }
              break;

            case GNUTLS_BAG_CRL:
              if (*crl != NULL)
                {
                  gnutls_assert ();
                  break;
                }

              ret = gnutls_x509_crl_init (crl);
              if (ret < 0)
                {
                  gnutls_assert ();
                  goto done;
                }

              ret = gnutls_x509_crl_import (*crl, &data, GNUTLS_X509_FMT_DER);
              if (ret < 0)
                {
                  gnutls_assert ();
                  gnutls_x509_crl_deinit (*crl);
                  goto done;
                }
              break;

            case GNUTLS_BAG_ENCRYPTED:
              /* XXX Bother to recurse one level down?  Unlikely to
                 use the same password anyway. */
            case GNUTLS_BAG_EMPTY:
            default:
              break;
            }
        }

      idx++;
      gnutls_pkcs12_bag_deinit (bag);
    }

  ret = 0;

done:
  if (bag)
    gnutls_pkcs12_bag_deinit (bag);

  if (ret)
    {
      if (*key)
        gnutls_x509_privkey_deinit(*key);
      if (*cert)
        gnutls_x509_crt_deinit(*cert);
      if (extra_certs_len)
        {
          int i;
          for (i = 0; i < extra_certs_len; i++)
            gnutls_x509_crt_deinit(extra_certs[i]);
          gnutls_free(extra_certs);
        }
    }
  else if (extra_certs_ret)
    {
      *extra_certs_ret = extra_certs;
      *extra_certs_ret_len = extra_certs_len;
    }

  return ret;
}
