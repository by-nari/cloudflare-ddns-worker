/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import Cloudflare from 'cloudflare';
import RecordCreateParams from 'cloudflare/resources/dns/records';
import { Buffer } from "node:buffer";
import { Address4, Address6 } from "ip-address";

const encoder = new TextEncoder();

function timingSafeEqual(a: string, b: string) {
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);

	if (aBytes.byteLength !== bBytes.byteLength) {
		// Strings must be the same length in order to compare
		// with crypto.subtle.timingSafeEqual
		return false;
	}

	return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const cloudflare = new Cloudflare({
			apiToken: env.CF_API_TOKEN,
		});

		const { searchParams } = new URL(request.url)

		// The "Authorization" header is sent when authenticated.
		const authorization = request.headers.get("Authorization");
		if (!authorization) {
			return new Response("You need to login.", {
				status: 401,
				headers: {
					// Prompts the user for credentials.
					"WWW-Authenticate": 'Basic realm="my scope", charset="UTF-8"',
				},
			});
		}
		const [scheme, encoded] = authorization.split(" ");

		// The Authorization header must start with Basic, followed by a space.
		if (!encoded || scheme !== "Basic") {
			return new Response("Malformed authorization header.", {
				status: 400,
			});
		}

		const credentials = Buffer.from(encoded, "base64").toString();

		// The username & password are split by the first colon.
		//=> example: "username:password"
		const index = credentials.indexOf(":");
		const user = credentials.substring(0, index);
		const pass = credentials.substring(index + 1);

		if (
			!timingSafeEqual(env.BASIC_USER, user) ||
			!timingSafeEqual(env.BASIC_PASS, pass)
		) {
			return new Response("You need to login.", {
				status: 401,
				headers: {
					// Prompts the user for credentials.
					"WWW-Authenticate": 'Basic realm="Cloudflare DDNS Worker", charset="UTF-8"',
				},
			});
		}

		const hostname = searchParams.get('hostname')
		const myip = searchParams.get('myip')

		// If no hostname is provided, return an error
		if (!hostname) {
			return new Response('No hostname provided', { status: 400 });
		}

		// If no myip is provided, return an error
		if (!myip) {
			return new Response('No myip provided', { status: 400 });
		}

		const zones = await cloudflare.zones.list();

		// If the zone is not found, return an error
		const zone = zones.result.find((z) => hostname.endsWith(z.name));
		if (!zone) {
			return new Response('Zone not found', { status: 400 });
		}

		try {
			const address = Address4.isValid(myip) ? new Address4(myip) : Address6.isValid(myip) ? new Address6(myip) : null;

			// If the IP address is invalid, return an error
			if (!address) {
				return new Response('Invalid IP address', { status: 400 });
			}

			const records = await cloudflare.dns.records.list({ zone_id: zone.id });

			// Find the record by name and type
			const record = records.result.find((r) => r.name === hostname);

			const baseRecord = {
				content: address.correctForm(),
				name: hostname === zone.name ? "@" : hostname.split(`.${zone.name}`)[0],
				ttl: 300,
				proxied: false,
			};

			let newRecord: RecordCreateParams.ARecord | RecordCreateParams.AAAARecord | null = null;

			if (Address4.isValid(myip)) {
				newRecord = {
					...baseRecord,
					type: "A",
				};
			} else if (Address6.isValid(myip)) {
				newRecord = {
					...baseRecord,
					type: "AAAA",
				};
			}

			// If newRecord is null, return an error
			if (!newRecord) {
				return new Response('Invalid IP address', { status: 400 });
			}

			// // If the record is not found, create a new record
			if (!record?.id) {
				await cloudflare.dns.records.create({ ...newRecord, zone_id: zone.id });

				return new Response('DNS record created successfully');
			}

			// Update the record with the new IP address
			if (record) {
				await cloudflare.dns.records.update(record.id, {
					...newRecord,
					zone_id: zone.id
				});
			}

			return new Response('DNS record updated successfully');
		} catch (error) {
			console.error(error);
			return new Response('Error modifying DNS record', { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
