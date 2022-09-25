const os = require('os');
const fs = require('fs/promises');
const { URL } = require('url');
const { decode: from_b32 } = require('thirty-two');

const TOTP = require('../totp');

const DEFAULT_NS = '0x00';
const DEFAULT_FILE = `${os.homedir()}/.control-otp`;

const bold = (text) => {
	return '\033[1m' + text + '\033[0m';
};

const gray = (text) => {
	return '\u001b[38;5;244m' + text + '\u001b[0m';
};

class OTPCli {
	constructor({ alg='sha1',  key, file }) {
		this.alg = alg;
		this.key = key ? from_b32(key) : null;
		this.file = file || DEFAULT_FILE;
	}

	read_config() {
		return fs.readFile(this.file, {
			encoding: 'utf8'
		}).then(file => {
			const data = Buffer.from(file, 'base64');
			const config = JSON.parse(data);

			return config;
		}).catch(e => {
			if(e.code === 'ENOENT' && this.file === DEFAULT_FILE) {
				// create file and return empty config
				return this.write_config().then(() => ({}));
			}

			throw e;
		});
	}

	write_config(config={}) {
		const data = JSON.stringify(config);
		const b64 = Buffer.from(data).toString('base64');
		return fs.writeFile(this.file, b64);
	}

	totp({ key, alg, period, date, digits }={}) {
		const totp = new TOTP({
			key,
			period,
			algorithm: alg,
		});

		return totp.code({
			digits,
			date
		});
	}

	from_config({ id, namespace=DEFAULT_NS }={}) {
		return this.read_config().then(config => {
			const ns = config[namespace];
			if(!ns) {
				throw new Error(`No namespace named "${namespace}"`);
			}

			const file_config = ns[id];

			if(!file_config && namespace === DEFAULT_NS) {
				// search all other namespaces
				for(const [namespace, namespace_entries] of Object.entries(config)) {
					if(namespace_entries[id]) {
						console.log(`Found ${bold(id)} on namespace ${bold(namespace)}`);
						return this.totp(namespace_entries[id]);
					}
				}

				throw new Error(`No config "${id}" on any namespace`);

			}

			if(!file_config) {
				throw new Error(`No config "${id}" on namespace "${namespace}"`);
			}

			return this.totp(file_config);
		});
	}

	generate({ digits, period, date }) {
		if(!this.key) {
			throw new Error('key is mandatory when generating custom TOTP code');
		}

		return Promise.resolve(this.totp({
			digits,
			period,
			date,
			key: this.key,
			alg: this.alg
		}));
	}

	save({ id, url, namespace, key, period, digits }={}) {
		if(namespace === DEFAULT_NS) {
			throw new Error('namespace 0x00 is reserved');
		}

		let params = {};
		if(url) {
			const parsed_url = new URL(url);
			if(parsed_url.protocol !== 'otpauth:') {
				throw new Error('URL is malformed (protocol must be "otpauth:")');
			}

			const key = parsed_url.searchParams.get('secret');

			if(!key) {
				throw new Error('URL is malformed (secret is mandatory)');
			}

			params = {
				key: from_b32(key),
				id: decodeURIComponent(parsed_url.searchParams.get('issuer')),
				name: decodeURIComponent(parsed_url.pathname.replace(/^\//, '')),
				alg: parsed_url.searchParams.get('algorithm') || this.alg,
				digits: parsed_url.searchParams.get('digits') || 6,
				period: parsed_url.searchParams.get('period') || 30,
			};
		} else {
			if(!id) {
				throw new Error('--id is mandatory if saving manually (not from url)');
			}

			if(!this.alg) {
				throw new Error('--alg is mandatory if saving manually (not from url)');
			}

			if(!this.key) {
				throw new Error('--key is mandatory if saving manually (not from url)');
			}

			params = {
				id,
				alg: this.alg,
				key: this.key,
				digits,
				period,
			};
		}

		return this.read_config().then(config => {
			namespace = namespace || DEFAULT_NS;
			config[namespace] = config[namespace] || {};

			config[namespace][params.id] = params;

			return this.write_config(config);
		}).then(() => {
			console.log('✨ Done!');
		}).catch(e => { throw e; });
	}

	list() {
		return this.read_config().then(namespaces => {
			const ns_list = Object.entries(namespaces).reduce((agg, [name, entries]) => {
				if(name === DEFAULT_NS) {
					name = 'No namespace'
				};

				const config_entries = Object.entries(entries).reduce((entries, [id, config]) => {
					const { name } = config;
					const formatted_name = name ? `${name} - ` : '';
					entries.push(`\t${formatted_name}${gray(id)}`);
					return entries;
				}, []);

				const entries_text = config_entries.join('\n');

				agg.push(
					`${bold(name)}\n${entries_text}`
				);

				return agg;
			}, []);

			console.log(ns_list.join('\n'));
		});
	}
}

module.exports = OTPCli;
