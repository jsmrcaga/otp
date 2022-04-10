#!/usr/bin/env node

const OTPCLI = require('./cli');

let argumentate = null;

try {
	argumentate = require('argumentate');
} catch(e) {
	console.error('You need to install optional dependency "argumentate" to use cli');
	process.exit(1);
}

const { options, variables } = argumentate({
	args: process.argv.slice(2),
	mapping: {
		a: {
			key: 'alg',
			help: 'Hashing algorithm to use, valid options are sha1, sha256 and sha512. Default will be sha256'
		},
		k: {
			key: 'key',
			help: 'They secret key to use'
		},
		x: {
			key: 'digits',
			help: 'The length of the code to generate'
		},
		d: {
			key: 'date',
			help: 'The date to use (in ISOString UTC or seconds since epoch)'
		},
		p: {
			key: 'period',
			help: 'The period (in seconds) to use in TOTP mode. Default is 30 seconds'
		},
		f: {
			key: 'file',
			help: 'The path of the config file to use'
		},
		u: {
			key: 'url',
			help: 'The url to store the 2FA information'
		},
		n: {
			key: 'namespace',
			help: 'The namespace from or to which get/store the 2FA info'
		},
		s: {
			key: 'save',
			help: 'Used to save 2FA information instead of generating a code'
		},
		l: {
			key: 'list',
			help: 'Show list of namespaces and saved codes'
		}
	},
	config: {
		name: '@control/otp',
		command: 'otp'
	}
});

const {
	alg = 'sha256',
	digits = 6,
	period = 30,
	date,
	key,
	file,
	namespace,
	save,
	url,
	list
} = options;

const [id] = variables;

const otp = new OTPCLI({
	alg,
	key,
	file,
});

try {
	if(list || (!id && !save)) {
		return otp.list().catch(e => {
			console.error(e);
			process.exit(1);
		});
	}

	if(save) {
		// Save config info into file
		return otp.save({
			url,
			namespace,
			key,
			period,
			digits,
			// Id is included in case we want to override
			id
		});
	}

	let code = null;

	if(id) {
		// Get data from config
		code = otp.from_config({
			namespace,
			id
		});
	} else {
		// handle ISO string
		const custom_date = date ? (Number.isNaN(date) ? Number.parseInt(date) : new Date(date)) : undefined;
		// Get data from args
		code = otp.generate({
			digits,
			period,
			date: custom_date
		});
	}

	code.then(otp => {
		console.log('One-time password is\n\n\t\033[1m', otp, '\033[0m\n');
	}).catch(e => {
		console.error(e.message);
		process.exit(1);
	});
} catch(e) {
	console.error(e.message);
	process.exit(1);
}
