#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_ecdh.h"
#include "openssl/ssl.h"
#include "openssl/md5.h"

#define MALLOC_SIZE 0x200u

// #define __debug__
#ifdef __debug__
#include <string.h>
int hex2bin(unsigned char* src, int srclen, unsigned char* dest) {
	int i = 0;
	if (srclen % 2 != 0) return 0;
	for (i = 0; i < srclen / 2; i++)
	{
		char tmp[3];
		tmp[0] = *(src + 2 * i);
		tmp[1] = *(src + 2 * i + 1);
		tmp[2] = 0;
		int out = 0;
		sscanf(tmp, "%x", &out);
		unsigned char ch = (unsigned char)out;
		*(dest + i) = ch;
	}
	return i;
}

int bin2hex(unsigned char* src, int srclen, unsigned char* dest) {
	int i;
	for (i = 0; i < srclen; i++)
	{
		char tmp[3] = { 0 };
		sprintf(tmp, "%x", *(src + i));
		if (strlen(tmp) == 1) {
			strcat((char*)dest, "0");
			strncat((char*)dest, tmp, 1);
		}
		else if (strlen(tmp) == 2) {
			strncat((char*)dest, tmp, 2);
		}
		else {
			strcat((char*)dest, "00");
		}
	}
	return i * 2;
}

static void display(const char* tripstr, const char* src, const int src_size)
{
	int i = 0;
	if (tripstr != NULL) {
		printf("%s", tripstr);
	}
	unsigned char* tmp = (unsigned char*)malloc(MALLOC_SIZE);
	memset(tmp, 0, MALLOC_SIZE);
	bin2hex((unsigned char*)src, src_size, tmp);

	printf("%s\n", tmp);
	free(tmp);
}
#endif


PHP_FUNCTION( ecdh_compute_key )
{
	char * prikey;
	char * srvpub;
	size_t prikey_len;
	size_t srvpub_len;

	ZEND_PARSE_PARAMETERS_START( 2, 2 )
	Z_PARAM_STRING( prikey, prikey_len )
	Z_PARAM_STRING( srvpub, srvpub_len )
	ZEND_PARSE_PARAMETERS_END();

	unsigned char* shared = (unsigned char*)malloc(MALLOC_SIZE);
	memset(shared, 0, MALLOC_SIZE);
	unsigned char* sharekey = (unsigned char*)malloc(MALLOC_SIZE);
	memset(sharekey, 0, MALLOC_SIZE);

	EC_KEY* ec_key;
	const EC_GROUP* group;
	const EC_POINT* point;
	// 椭圆曲线 711 NID_secp192k1
	ec_key = EC_KEY_new_by_curve_name(NID_secp192k1);

	// 导入客户端prikey
	BIGNUM* bn = BN_new();
	BN_mpi2bn((const unsigned char*)prikey, prikey_len, bn);
	EC_KEY_set_private_key(ec_key, bn);
	BN_free(bn);

	// 导入服务端pubkey
	group = EC_KEY_get0_group(ec_key);
	point = EC_POINT_new(group);
	EC_POINT_oct2point(group, (EC_POINT*)point, (const unsigned char*)srvpub, srvpub_len, NULL);

	// 计算sharekey 长度
	int share_key_length;
	share_key_length = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
	share_key_length = (share_key_length + 7) / 8;

	// 计算 shared key
	int shared_len = ECDH_compute_key(shared, share_key_length, point, ec_key, NULL);

	MD5(shared, shared_len, sharekey);

#ifdef __debug__
	display("prikey : ", (const char*)prikey, prikey_len);
	display("srvpub : ", (const char*)srvpub, srvpub_len);
	display("shared : ", (const char*)shared, shared_len);
	display("sharekey : ", (const char*)sharekey, MD5_DIGEST_LENGTH);
#endif

	array_init(return_value);
	add_next_index_stringl(return_value, shared, shared_len);
	add_next_index_stringl(return_value, sharekey, MD5_DIGEST_LENGTH);

	EC_KEY_free(ec_key);
	free(shared);
	free(sharekey);
}

PHP_FUNCTION( ecdh_generate_key )
{
	unsigned char* prikey = (unsigned char*)malloc(MALLOC_SIZE);
	memset(prikey, 0, MALLOC_SIZE);
	unsigned char* pubkey = (unsigned char*)malloc(MALLOC_SIZE);
	memset(pubkey, 0, MALLOC_SIZE);
	unsigned char* shared = (unsigned char*)malloc(MALLOC_SIZE);
	memset(shared, 0, MALLOC_SIZE);
	unsigned char* sharekey = (unsigned char*)malloc(MALLOC_SIZE);
	memset(sharekey, 0, MALLOC_SIZE);

	char * srvpub;
	size_t srvpub_len;

	ZEND_PARSE_PARAMETERS_START( 1, 1 )
	Z_PARAM_STRING( srvpub, srvpub_len )
	ZEND_PARSE_PARAMETERS_END();

	EC_KEY* ec_key;
	const EC_GROUP* group;
	const EC_POINT* point;

	// 椭圆曲线 711 NID_secp192k1
	ec_key = EC_KEY_new_by_curve_name(NID_secp192k1);

	// 生成公钥私钥
	EC_KEY_generate_key(ec_key);

	// 获取公钥
	group = EC_KEY_get0_group(ec_key);
	point = EC_KEY_get0_public_key(ec_key);
	int pubkey_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubkey, MALLOC_SIZE, NULL);

	// 获取私钥
	const BIGNUM* bn = EC_KEY_get0_private_key(ec_key);
	int prikey_len = BN_bn2mpi(bn, prikey);

	// 导入服务端pubkey
	group = EC_KEY_get0_group(ec_key);
	point = EC_POINT_new(group);
	EC_POINT_oct2point(group, (EC_POINT*)point, (const unsigned char*)srvpub, srvpub_len, NULL);

	// 计算sharekey 长度
	int share_key_length;
	share_key_length = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
	share_key_length = (share_key_length + 7) / 8;

	// 计算 shared key
	int shared_len = ECDH_compute_key(shared, share_key_length, point, ec_key, NULL);
	// md5
	MD5(shared, shared_len, sharekey);

#ifdef __debug__
	display("prikey : ", (const char*)prikey, prikey_len);
	display("pubkey : ", (const char*)pubkey, pubkey_len);
	display("shared : ", (const char*)shared, shared_len);
	display("sharekey : ", (const char*)sharekey, MD5_DIGEST_LENGTH);
#endif

	array_init(return_value);
	add_next_index_stringl(return_value, prikey, prikey_len);
	add_next_index_stringl(return_value, pubkey, pubkey_len);
	add_next_index_stringl(return_value, shared, shared_len);
	add_next_index_stringl(return_value, sharekey, MD5_DIGEST_LENGTH);

	// 释放内存
	EC_KEY_free(ec_key);
	free(prikey);
	free(pubkey);
	free(shared);
	free(sharekey);
}

/* {{{ php_ecdh_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_ecdh_init_globals(zend_ecdh_globals *ecdh_globals)
{
	ecdh_globals->global_value = 0;
	ecdh_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(ecdh)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(ecdh)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(ecdh)
{
#if defined(COMPILE_DL_ECDH) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(ecdh)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(ecdh)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "ecdh support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ ecdh_functions[]
 *
 * Every user visible function must have an entry in ecdh_functions[].
 */
const zend_function_entry ecdh_functions[] = {
	PHP_FE(ecdh_compute_key, NULL)
	PHP_FE(ecdh_generate_key, NULL)
	PHP_FE_END	/* Must be the last line in ecdh_functions[] */
};
/* }}} */

/* {{{ ecdh_module_entry
 */
zend_module_entry ecdh_module_entry = {
	STANDARD_MODULE_HEADER,
	"ecdh",
	ecdh_functions,
	PHP_MINIT(ecdh),
	PHP_MSHUTDOWN(ecdh),
	PHP_RINIT(ecdh),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(ecdh),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(ecdh),
	PHP_ECDH_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_ECDH
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(ecdh)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
