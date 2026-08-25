/**
 * DHCPv4 options configured with `list dhcp_option`.
 *
 * Copyright (C) 2026 the odhcpd authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 */
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dhcpv4-options.h"

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

enum dhcpv4_option_ftype {
	FTYPE_INFER,	/* IPv4 list if every value parses, else string */
	FTYPE_IP,
	FTYPE_U8,
	FTYPE_U16,
	FTYPE_U32,
	FTYPE_STRING,
	FTYPE_HEX,
};

/*
 * The dnsmasq names in common use, with the type that stops a value being
 * encoded as the wrong thing: without it mtu would go out as the four
 * characters "1500". Any other option is still available by number, where an
 * IPv4 list is recognised, 0x... is raw bytes and anything else is a string.
 */
static const struct {
	const char *name;
	uint8_t code;
	enum dhcpv4_option_ftype type;
} option_names[] = {
	{ "netmask",		1,	FTYPE_IP },
	{ "router",		3,	FTYPE_IP },
	{ "dns-server",		6,	FTYPE_IP },
	{ "domain-name",	15,	FTYPE_STRING },
	{ "mtu",		26,	FTYPE_U16 },
	{ "broadcast",		28,	FTYPE_IP },
	{ "ntp-server",		42,	FTYPE_IP },
	{ "lease-time",		51,	FTYPE_U32 },
	{ "tftp-server",	66,	FTYPE_STRING },
	{ "bootfile-name",	67,	FTYPE_STRING },
	{ "classless-static-route", 121, FTYPE_HEX },
};

const char *dhcpv4_option_strerror(enum dhcpv4_option_status status)
{
	switch (status) {
	case DHCPV4_OPTION_OK:
		return "ok";
	case DHCPV4_OPTION_BAD_SYNTAX:
		return "expected <name|code>,<value>";
	case DHCPV4_OPTION_UNKNOWN:
		return "unknown option";
	case DHCPV4_OPTION_BAD_VALUE:
		return "value does not fit the option";
	case DHCPV4_OPTION_NOMEM:
		return "out of memory";
	}

	return "unknown error";
}

static enum dhcpv4_option_ftype type_for_code(uint8_t code)
{
	for (size_t i = 0; i < ARRAY_LEN(option_names); i++) {
		if (option_names[i].code == code)
			return option_names[i].type;
	}

	return FTYPE_INFER;
}

static int code_of(const char *key, enum dhcpv4_option_ftype *type)
{
	char *end;
	unsigned long code;

	if (!strncmp(key, "option:", 7))
		key += 7;

	code = strtoul(key, &end, 10);
	if (*key && !*end) {
		if (code < 1 || code > 254)
			return -1;

		*type = type_for_code(code);
		return code;
	}

	for (size_t i = 0; i < ARRAY_LEN(option_names); i++) {
		if (strcmp(key, option_names[i].name))
			continue;

		*type = option_names[i].type;
		return option_names[i].code;
	}

	return -1;
}

static ssize_t encode_hex(const char *value, uint8_t *buf, size_t buflen)
{
	size_t len = 0;

	if (!strncmp(value, "0x", 2))
		value += 2;

	while (*value) {
		char pair[3] = { value[0], value[1], 0 };
		char *end;
		unsigned long byte;

		if (!value[1] || len >= buflen)
			return -1;

		byte = strtoul(pair, &end, 16);
		if (*end)
			return -1;

		buf[len++] = byte;
		value += 2;

		if (*value == ':' || *value == '-')
			value++;
	}

	return (ssize_t)len;
}

static ssize_t encode(const char *value, enum dhcpv4_option_ftype type,
		      uint8_t *buf, size_t buflen)
{
	size_t len = 0;
	unsigned width = 0;

	if (!strncmp(value, "0x", 2))
		return encode_hex(value, buf, buflen);

	switch (type) {
	case FTYPE_STRING:
		len = strlen(value);
		if (len > buflen)
			return -1;
		memcpy(buf, value, len);
		return (ssize_t)len;

	case FTYPE_HEX:
		return encode_hex(value, buf, buflen);

	case FTYPE_U8:
		width = 1;
		break;
	case FTYPE_U16:
		width = 2;
		break;
	case FTYPE_U32:
		width = 4;
		break;
	default:
		break;
	}

	if (!*value)
		return -1;

	while (*value) {
		const char *comma = strchr(value, ',');
		size_t vlen = comma ? (size_t)(comma - value) : strlen(value);
		char item[64];

		if (vlen == 0 || vlen >= sizeof(item))
			return -1;

		memcpy(item, value, vlen);
		item[vlen] = 0;

		if (width) {
			char *end;
			unsigned long long num = strtoull(item, &end, 0);

			if (*end || len + width > buflen)
				return -1;
			if (num >> (width * 8))
				return -1;

			for (unsigned i = 0; i < width; i++)
				buf[len + i] = (num >> ((width - 1 - i) * 8)) & 0xff;
			len += width;
		} else {
			struct in_addr addr;

			if (inet_pton(AF_INET, item, &addr) != 1)
				return -1;
			if (len + sizeof(addr) > buflen)
				return -1;

			memcpy(buf + len, &addr, sizeof(addr));
			len += sizeof(addr);
		}

		if (!comma)
			break;
		value = comma + 1;
	}

	return (ssize_t)len;
}

enum dhcpv4_option_status dhcpv4_option_parse(const char *spec, uint8_t **opts,
					      size_t *opts_len)
{
	enum dhcpv4_option_ftype type = FTYPE_INFER;
	const char *comma;
	uint8_t buf[UINT8_MAX];
	char key[64];
	ssize_t len;
	uint8_t *tmp;
	int code;

	if (!spec || !opts || !opts_len)
		return DHCPV4_OPTION_BAD_SYNTAX;

	comma = strchr(spec, ',');
	if (!comma || comma == spec || (size_t)(comma - spec) >= sizeof(key))
		return DHCPV4_OPTION_BAD_SYNTAX;

	memcpy(key, spec, comma - spec);
	key[comma - spec] = 0;

	code = code_of(key, &type);
	if (code < 0)
		return DHCPV4_OPTION_UNKNOWN;

	len = encode(comma + 1, type, buf, sizeof(buf));
	if (len < 0 && type == FTYPE_INFER)
		len = encode(comma + 1, FTYPE_STRING, buf, sizeof(buf));

	if (len < 0)
		return DHCPV4_OPTION_BAD_VALUE;

	tmp = realloc(*opts, *opts_len + 2 + (size_t)len);
	if (!tmp)
		return DHCPV4_OPTION_NOMEM;

	*opts = tmp;
	tmp += *opts_len;
	tmp[0] = (uint8_t)code;
	tmp[1] = (uint8_t)len;
	memcpy(tmp + 2, buf, (size_t)len);
	*opts_len += 2 + (size_t)len;

	return DHCPV4_OPTION_OK;
}

bool dhcpv4_option_present(const uint8_t *opts, size_t opts_len, uint8_t code)
{
	if (!opts)
		return false;

	for (size_t i = 0; i + 1 < opts_len; i += 2 + opts[i + 1]) {
		if (opts[i] == code)
			return true;
	}

	return false;
}

size_t dhcpv4_option_copy(uint8_t *dst, size_t cap, size_t used,
			  const uint8_t *opts, size_t opts_len, uint8_t code)
{
	if (!opts)
		return used;

	for (size_t i = 0; i + 1 < opts_len; i += 2 + opts[i + 1]) {
		size_t tlv = 2 + opts[i + 1];

		if (code && opts[i] != code)
			continue;
		if (dhcpv4_option_present(dst, used, opts[i]))
			continue;
		if (used + tlv > cap)
			continue;

		memcpy(dst + used, opts + i, tlv);
		used += tlv;
	}

	return used;
}
