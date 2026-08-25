/**
 * DHCPv4 options configured with `list dhcp_option`.
 *
 * Kept apart from config.c so that the encoder can be linked, and therefore
 * tested and fuzzed, without the rest of the daemon: it turns operator input
 * into wire bytes with its own length arithmetic, which is worth exercising
 * directly.
 *
 * Copyright (C) 2026 the odhcpd authors
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum dhcpv4_option_status {
	DHCPV4_OPTION_OK = 0,
	DHCPV4_OPTION_BAD_SYNTAX,	/* no comma, or an over-long key */
	DHCPV4_OPTION_UNKNOWN,		/* not a code in 1..254 nor a known name */
	DHCPV4_OPTION_BAD_VALUE,	/* the value does not fit the option's type */
	DHCPV4_OPTION_NOMEM,
};

/**
 * dhcpv4_option_parse - encode one `list dhcp_option` entry
 * @spec: [option:]<name|code>,<value>[,<value>...], the dnsmasq syntax
 * @opts: option buffer to append to, reallocated as needed
 * @opts_len: its length, updated on success
 *
 * On any failure @opts and @opts_len are left as they were, so one bad entry
 * does not cost the entries around it.
 */
enum dhcpv4_option_status dhcpv4_option_parse(const char *spec, uint8_t **opts,
					      size_t *opts_len);

/** dhcpv4_option_strerror - a reason to put in a log line */
const char *dhcpv4_option_strerror(enum dhcpv4_option_status status);

/** dhcpv4_option_present - whether @code was configured */
bool dhcpv4_option_present(const uint8_t *opts, size_t opts_len, uint8_t code);

/**
 * dhcpv4_option_copy - copy configured options into a reply buffer
 * @dst: reply buffer
 * @cap: its size
 * @used: bytes already in it
 * @code: the option wanted, or 0 for every one of them
 *
 * Skips an option already in @dst, so the first writer of a code wins, and
 * skips one that does not fit rather than truncating it: a truncated option
 * is not a shorter option, it is a malformed reply.
 *
 * Return: the new used count.
 */
size_t dhcpv4_option_copy(uint8_t *dst, size_t cap, size_t used,
			  const uint8_t *opts, size_t opts_len, uint8_t code);
