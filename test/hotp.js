const Sinon = require('sinon');
const { expect } = require('chai');

const HOTP = require('../hotp');

describe('HOTP', () => {
	const rfc_example_secret = '12345678901234567890';

	describe('HMAC computation', () => {
		// Here we use test values from the spec
		// https://datatracker.ietf.org/doc/html/rfc4226#appendix-D
		for(const [count, hmac_result] of [
			[0, 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0'],
			[1, '75a48a19d4cbe100644e8ac1397eea747a2d33ab'],
			[2, '0bacb7fa082fef30782211938bc1c5e70416ff44'],
			[3, '66c28227d03a2d5529262ff016a1e6ef76557ece'],
			[4, 'a904c900a64b35909874b33e61c5938a8e15ed1c'],
			[5, 'a37e783d7b7233c083d4f62926c7a25f238d0316'],
			[6, 'bc9cd28561042c83f219324d3c607256c03272ae'],
			[7, 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa'],
			[8, '1b3c89f65e6c9e883012052823443f048b4332db'],
			[9, '1637409809a679dc698207310c8c7fc07290d9e5']
		]) {
			it(`Should compute the correct hmac value given the count (${count})`, () => {
				const hotp = new HOTP({
					key: rfc_example_secret,
				});

				const digest_buffer = hotp.compute_hmac({
					counter: hotp.compute_counter(count)
				});

				expect(digest_buffer.toString('hex')).to.be.eql(hmac_result);
			});
		}
	});

	describe('RFC 4226 Example codes', () => {
		for(const [count, example_hotp] of [
			[0, '755224'],
			[1, '287082'],
			[2, '359152'],
			[3, '969429'],
			[4, '338314'],
			[5, '254676'],
			[6, '287922'],
			[7, '162583'],
			[8, '399871'],
			[9, '520489']
		]) {
			it(`Should compute RFC example code for counter ${count}`, () => {
				const hotp = new HOTP({ key: rfc_example_secret });
				const code = hotp.code({ counter: count });
				expect(code).to.be.eql(example_hotp);
			});
		}
	});

	describe('Code', () => {
		let hmac_stub = null;
		before(() => {
			hmac_stub = Sinon.stub(HOTP.prototype, 'compute_hmac').callsFake(() => {
				// https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
				return Buffer.from([0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a]);
			});
		});

		it('Should compute RFC example code', () => {
			const hotp = new HOTP();

			const code = hotp.code();
			expect(code).to.be.eql('872921');
			expect(hmac_stub.calledOnce).to.be.true;
		});

		for(const length of [6, 7, 8]) {
			it(`Should compute codes with different lengths (${length})`, () => {
				const hotp = new HOTP();

				const code = hotp.code({ digits: length });
				expect(code.toString()).to.have.length(length);
			});
		}

		after(() => {
			hmac_stub.restore();
		});
	})
});
