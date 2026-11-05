import axios from 'axios';
import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { SDJWTVCVerifier } from './SDJWTVCVerifier';
import { CredentialVerificationError } from '../error';
import { toBase64Url } from '../utils/util';

// Node's KeyObject imports do not reproduce the browser's non-extractable
// CryptoKey default. Exercise JOSE's actual browser implementation with WebCrypto.
vi.mock('jose', async () => import('../../node_modules/jose/dist/browser/index.js'));

async function setup(ext?: boolean) {
	const issuer = await generateKeyPair('ES256', { extractable: true });
	const holder = await generateKeyPair('ES256', { extractable: true });
	const exportedHolder = await exportJWK(holder.publicKey);
	const holderJwk = {
		kty: exportedHolder.kty,
		crv: exportedHolder.crv,
		x: exportedHolder.x,
		y: exportedHolder.y,
		alg: 'ES256',
		...(ext === undefined ? {} : { ext }),
	};
	const issuerJwk = await exportJWK(issuer.publicKey);
	const credential =
		(await new SignJWT({
			iss: 'https://issuer.example',
			vct: 'https://issuer.example/diploma',
			cnf: { jwk: holderJwk },
		})
			.setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
			.setIssuedAt()
			.setExpirationTime('1h')
			.sign(issuer.privateKey)) + '~';
	const verifier = SDJWTVCVerifier({
		context: {
			clockTolerance: 0,
			lang: 'en-US',
			subtle: crypto.subtle,
			trustedCertificates: [],
		},
		pkResolverEngine: {
			register() {},
			async resolve() {
				return { success: true, value: { jwk: issuerJwk } };
			},
		},
		httpClient: axios,
	});
	return { credential, holder, holderJwk, verifier };
}

describe('SD-JWT verification with browser CryptoKeys', () => {
	it.each([undefined, false, true])('returns the public holder JWK when ext is %s', async (ext) => {
		const { credential, holderJwk, verifier } = await setup(ext);
		const result = await verifier.verify({ rawCredential: credential, opts: {} });

		expect(result.success).toBe(true);
		if (!result.success) throw new Error(`Verification failed: ${result.error}`);
		expect(result.value.holderPublicKey).toMatchObject({
			kty: holderJwk.kty,
			crv: holderJwk.crv,
			x: holderJwk.x,
			y: holderJwk.y,
		});
		expect(result.value.holderPublicKey).not.toHaveProperty('d');
	});

	it.each([true, false])(
		'verifies the key-binding signature (correct holder: %s)',
		async (correctHolder) => {
			const { credential, holder, verifier } = await setup();
			const signingKey = correctHolder ? holder : await generateKeyPair('ES256');
			const sdHash = toBase64Url(
				await crypto.subtle.digest('SHA-256', new TextEncoder().encode(credential)),
			);
			const kbJwt = await new SignJWT({
				sd_hash: sdHash,
				nonce: 'nonce',
				aud: 'https://verifier.example',
			})
				.setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
				.setIssuedAt()
				.sign(signingKey.privateKey);
			const result = await verifier.verify({
				rawCredential: credential + kbJwt,
				opts: { expectedNonce: 'nonce', expectedAudience: 'https://verifier.example' },
			});

			if (correctHolder) {
				expect(result.success).toBe(true);
			} else {
				expect(result).toEqual({
					success: false,
					error: CredentialVerificationError.KbJwtVerificationFailedSignatureValidation,
				});
			}
		},
	);
});
