import hashlib

import base58
import bitcoinlib
import eth_keys
from ecdsa import SECP256k1, VerifyingKey


def derive_child_key(near_address: str, near_public_key: str, path: str) -> bytes:
    """
    Derive a child key from a NEAR address and public key.

    :param near_address: The NEAR address (e.g., "felipe-near.testnet")
    :param near_public_key: The NEAR public key in base58 format
    :param path: The derivation path
    :return: The derived child public key
    """
    public_key_bytes = base58.b58decode(near_public_key.split(":")[1])

    derivation_string = f"near-mpc-recovery v0.1.0 epsilon derivation:{near_address},{path}"
    scalar = int.from_bytes(hashlib.sha256(derivation_string.encode()).digest(), "little")

    parent_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
    child_point = parent_key.pubkey.point + scalar * SECP256k1.generator

    return child_point.x().to_bytes(32, "big") + child_point.y().to_bytes(32, "big")


def derive_crypto_address(
    near_address: str, near_public_key: str, chain: str = "ethereum", bitcoin_network: str = "testnet"
) -> str:
    """
    Derive a cryptocurrency address from a NEAR address and public key.

    :param near_address: The NEAR address (e.g., "felipe-near.testnet")
    :param near_public_key: The NEAR public key in base58 format
    :param chain: The target blockchain ("ethereum" or "bitcoin")
    :param bitcoin_network: The Bitcoin network ("testnet" or "mainnet"), only used if chain is "bitcoin"
    :return: The derived cryptocurrency address
    """
    path = '{"chain":60}' if chain == "ethereum" else '{"chain":0}'
    child_public_key = derive_child_key(near_address, near_public_key, path)

    if chain == "ethereum":
        return eth_keys.keys.PublicKey(child_public_key).to_checksum_address()
    elif chain == "bitcoin":
        network = "testnet" if bitcoin_network == "testnet" else "bitcoin"
        return bitcoinlib.keys.Address(data=b"\x04" + child_public_key, network=network, script_type="p2pkh").address
    else:
        raise ValueError("Unsupported chain. Choose 'ethereum' or 'bitcoin'.")


# Example usage
if __name__ == "__main__":
    near_address = "felipe-near.testnet"
    near_public_key = (
        "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3"
    )

    eth_address = derive_crypto_address(near_address, near_public_key, "ethereum")
    btc_testnet_address = derive_crypto_address(near_address, near_public_key, "bitcoin", "testnet")
    btc_mainnet_address = derive_crypto_address(near_address, near_public_key, "bitcoin", "mainnet")

    print(f"Derived Ethereum address: {eth_address}")
    print(f"Derived Bitcoin testnet address: {btc_testnet_address}")
    print(f"Derived Bitcoin mainnet address: {btc_mainnet_address}")

    assert eth_address == "0x0E80ec32E58Cf38Eb69AC9Bff0AdB2E637dC49f5"
    assert btc_testnet_address == "mq3jS53tKSBGt3hfyDVaaKHQ37N3EWY7uQ"
    assert btc_mainnet_address == "1AXn91xuWQk26wE4FeXCkQ55B7mLL6CARB"
