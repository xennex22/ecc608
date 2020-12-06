#include "ecc608.h"

bool verify_device_cert(void)
{
	bool ret = false;
	mbedtls_x509_crt signer_cert = { 0 };
	mbedtls_x509_crt_init(&signer_cert);
	mbedtls_x509_crt device_cert = { 0 };
	mbedtls_x509_crt_init(&device_cert);
	do
	{
		uint8_t cert_buf[1024] = {  0 };
		size_t cert_size;
		cert_size = sizeof(cert_buf);
		if(atcacert_read_cert(&cert_def_signer, key_root_public, cert_buf, &cert_size) != ATCACERT_E_SUCCESS)
		{
			debug_printf("atcacert_read_cert failed\r\n");
			break;
		}

//		FILE * certfile;
//		certfile = fopen("D:\\dev\\signing\\Certificates\\signer.test.der", "wb");
//		if(certfile != NULL)
//		{
//			fwrite(cert_buf, sizeof(uint8_t), cert_size, certfile);
//			fclose(certfile);
//		}

		uint8_t signer_public_key[64] = { 0 };
		if(atcacert_get_subj_public_key(&cert_def_signer, cert_buf, cert_size, signer_public_key) != ATCACERT_E_SUCCESS)
		{
			debug_printf("could not extract signer public key");
			break;
		}

		if(mbedtls_x509_crt_parse_der(&signer_cert, cert_buf, cert_size) != 0)
		{
			debug_printf("could not parse signer cert\r\n");
			break;
		}

		uint32_t flags;
		flags = 0;
		if(mbedtls_x509_crt_verify(&root_cert.cert, &root_cert.cert, NULL, NULL, &flags, NULL, NULL) != 0)
		{
			debug_printf("could not verify root cert\r\n");
			char buf[100] = { 0 };
			mbedtls_x509_crt_verify_info(buf, sizeof buf, "", flags);
      debug_printf(buf);
			break;
		}

		flags = 0;
		if(mbedtls_x509_crt_verify(&signer_cert, &root_cert.cert, NULL, NULL, &flags, NULL, NULL) != 0)
		{
			debug_printf("could not verify signer to root cert");
			char buf[100] = { 0 };
			mbedtls_x509_crt_verify_info(buf, sizeof buf, "", flags);
      debug_printf(buf);
			break;
		}

		cert_size = sizeof(cert_buf);
		if(atcacert_read_cert(&cert_def_device, signer_public_key, cert_buf, &cert_size) != ATCACERT_E_SUCCESS)
		{
			debug_printf("atcacert_read_cert failed\r\n");
			break;
		}

		if(mbedtls_x509_crt_parse_der(&device_cert, cert_buf, cert_size) != 0)
		{
			debug_printf("could not parse device cert\r\n");
			break;
		}

//		FILE * certfile;
//		certfile = fopen("D:\\dev\\signing\\Certificates\\device.test.der", "wb");
//		if(certfile != NULL)
//		{
//			fwrite(cert_buf, sizeof(uint8_t), cert_size, certfile);
//			fclose(certfile);
//		}

		flags = 0;
		if(mbedtls_x509_crt_verify(&device_cert, &signer_cert, NULL, NULL, &flags, NULL, NULL) != 0)
		{
			debug_printf("could not verify device to signer cert");
			char buf[100] = { 0 };
			mbedtls_x509_crt_verify_info(buf, sizeof buf, "", flags);
      debug_printf(buf);
			break;
		}

		uint8_t g_challenge[32] = { 0 };
		if(atcacert_gen_challenge_hw(g_challenge) != ATCACERT_E_SUCCESS)
		{
			debug_printf("atcacert_gen_challenge_hw failed with an error %d\r\n", ret);
			break;
		}

		uint8_t g_response[64] = { 0 };
		if(atcacert_get_response(cert_def_device.private_key_slot, g_challenge, g_response) != ATCACERT_E_SUCCESS)
		{
			debug_printf("atcacert_get_response failed with an error %d\r\n", ret);
			break;
		}

		uint8_t device_public_key[64] = { 0 };
		if(atcacert_get_subj_public_key(&cert_def_device, cert_buf, cert_size, device_public_key) != ATCACERT_E_SUCCESS)
		{
			debug_printf("could not get device public key");
			break;
		}

		if(atcacert_verify_response_hw(device_public_key, g_challenge, g_response) != ATCACERT_E_SUCCESS)
		{
			debug_printf("atcacert_verify_response_hw failed with an error %d\r\n", ret);
			break;
		}

    debug_printf("device verify ok");
		ret = true;
	} while(0);

	mbedtls_x509_crt_free(&signer_cert);
	mbedtls_x509_crt_free(&device_cert);
	return ret;
}
