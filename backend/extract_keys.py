#!/usr/bin/env python3
"""
Extract private keys from mnemonic for all supported chains
Usage: python3 extract_keys.py
"""

import sys
from mnemonic import Mnemonic
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip32Slip10Secp256k1, Bip32Slip10Ed25519
)

def derive_keys_from_mnemonic(mnemonic_phrase):
    """
    Derive private keys for all supported chains from a mnemonic
    
    Returns dict with currency code as key and private key as value
    """
    
    # Validate mnemonic
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic_phrase):
        raise ValueError("Invalid mnemonic phrase")
    
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic_phrase).Generate()
    
    keys = {}
    
    # ============================================
    # BITCOIN (BTC)
    # Path: m/44'/0'/0'/0/0
    # ============================================
    try:
        bip44_btc_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        btc_account = bip44_btc_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['BTC'] = btc_account.PrivateKey().Raw().ToHex()
        print("✓ BTC key derived")
    except Exception as e:
        print(f"✗ BTC key failed: {e}")
    
    # ============================================
    # ETHEREUM (ETH) - Also handles USDT-ERC20, USDC-ERC20
    # Path: m/44'/60'/0'/0/0
    # ============================================
    try:
        bip44_eth_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        eth_account = bip44_eth_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['ETH'] = '0x' + eth_account.PrivateKey().Raw().ToHex()
        print("✓ ETH key derived (also works for USDT-ERC20, USDC-ERC20)")
    except Exception as e:
        print(f"✗ ETH key failed: {e}")
    
    # ============================================
    # BINANCE SMART CHAIN (BNB) - Also handles USDT-BEP20
    # Path: m/44'/60'/0'/0/0 (same as ETH, compatible)
    # ============================================
    try:
        # BSC uses same derivation as Ethereum
        keys['BNB'] = keys['ETH']  # Same key works for BSC
        print("✓ BNB key derived (same as ETH, also works for USDT-BEP20)")
    except Exception as e:
        print(f"✗ BNB key failed: {e}")
    
    # ============================================
    # POLYGON (MATIC)
    # Path: m/44'/60'/0'/0/0 (same as ETH, compatible)
    # ============================================
    try:
        # Polygon uses same derivation as Ethereum
        keys['MATIC'] = keys['ETH']
        print("✓ MATIC key derived (same as ETH)")
    except Exception as e:
        print(f"✗ MATIC key failed: {e}")
    
    # ============================================
    # AVALANCHE (AVAX)
    # Path: m/44'/60'/0'/0/0 (same as ETH, compatible)
    # ============================================
    try:
        # Avalanche C-Chain uses same derivation as Ethereum
        keys['AVAX'] = keys['ETH']
        print("✓ AVAX key derived (same as ETH)")
    except Exception as e:
        print(f"✗ AVAX key failed: {e}")
    
    # ============================================
    # LITECOIN (LTC)
    # Path: m/44'/2'/0'/0/0
    # ============================================
    try:
        bip44_ltc_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.LITECOIN)
        ltc_account = bip44_ltc_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['LTC'] = ltc_account.PrivateKey().Raw().ToHex()
        print("✓ LTC key derived")
    except Exception as e:
        print(f"✗ LTC key failed: {e}")
    
    # ============================================
    # DOGECOIN (DOGE)
    # Path: m/44'/3'/0'/0/0
    # ============================================
    try:
        bip44_doge_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.DOGECOIN)
        doge_account = bip44_doge_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['DOGE'] = doge_account.PrivateKey().Raw().ToHex()
        print("✓ DOGE key derived")
    except Exception as e:
        print(f"✗ DOGE key failed: {e}")
    
    # ============================================
    # BITCOIN CASH (BCH)
    # Path: m/44'/145'/0'/0/0
    # ============================================
    try:
        bip44_bch_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN_CASH)
        bch_account = bip44_bch_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['BCH'] = bch_account.PrivateKey().Raw().ToHex()
        print("✓ BCH key derived")
    except Exception as e:
        print(f"✗ BCH key failed: {e}")
    
    # ============================================
    # RIPPLE (XRP)
    # Path: m/44'/144'/0'/0/0
    # ============================================
    try:
        bip44_xrp_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.RIPPLE)
        xrp_account = bip44_xrp_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['XRP'] = xrp_account.PrivateKey().Raw().ToHex()
        print("✓ XRP key derived")
    except Exception as e:
        print(f"✗ XRP key failed: {e}")
    
    # ============================================
    # SOLANA (SOL) - Also handles USDT-SOL
    # Path: m/44'/501'/0'/0'
    # ============================================
    try:
        bip44_sol_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
        sol_account = bip44_sol_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        # Solana uses base58 encoded private key
        sol_private_key_bytes = sol_account.PrivateKey().Raw().ToBytes()
        import base58
        keys['SOL'] = base58.b58encode(sol_private_key_bytes).decode('utf-8')
        print("✓ SOL key derived (also works for USDT-SOL)")
    except Exception as e:
        print(f"✗ SOL key failed: {e}")
    
    # ============================================
    # TRON (TRX) - Also handles USDT-TRON
    # Path: m/44'/195'/0'/0/0
    # ============================================
    try:
        bip44_trx_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)
        trx_account = bip44_trx_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['TRX'] = trx_account.PrivateKey().Raw().ToHex()
        print("✓ TRX key derived (also works for USDT-TRON)")
    except Exception as e:
        print(f"✗ TRX key failed: {e}")
    
    # ============================================
    # COSMOS (ATOM)
    # Path: m/44'/118'/0'/0/0
    # ============================================
    try:
        bip44_atom_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.COSMOS)
        atom_account = bip44_atom_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['ATOM'] = atom_account.PrivateKey().Raw().ToHex()
        print("✓ ATOM key derived")
    except Exception as e:
        print(f"✗ ATOM key failed: {e}")
    
    # ============================================
    # STELLAR (XLM)
    # Path: m/44'/148'/0'
    # ============================================
    try:
        bip44_xlm_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.STELLAR)
        xlm_account = bip44_xlm_ctx.Purpose().Coin().Account(0)
        keys['XLM'] = xlm_account.PrivateKey().Raw().ToHex()
        print("✓ XLM key derived")
    except Exception as e:
        print(f"✗ XLM key failed: {e}")
    
    # ============================================
    # CARDANO (ADA)
    # Path: m/44'/1815'/0'/0/0
    # ============================================
    try:
        bip44_ada_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.CARDANO)
        ada_account = bip44_ada_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['ADA'] = ada_account.PrivateKey().Raw().ToHex()
        print("✓ ADA key derived")
    except Exception as e:
        print(f"✗ ADA key failed: {e}")
    
    # ============================================
    # POLKADOT (DOT)
    # Path: m/44'/354'/0'/0/0
    # ============================================
    try:
        bip44_dot_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.POLKADOT)
        dot_account = bip44_dot_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        keys['DOT'] = dot_account.PrivateKey().Raw().ToHex()
        print("✓ DOT key derived")
    except Exception as e:
        print(f"✗ DOT key failed: {e}")
    
    return keys


def format_env_output(keys):
    """Format keys as .env file entries"""
    print("\n" + "="*60)
    print("COPY THESE TO YOUR .env FILE:")
    print("="*60 + "\n")
    
    for currency, private_key in sorted(keys.items()):
        print(f"{currency}_FEE_ADDY_PRIVATE_KEY={private_key}")
    
    print("\n" + "="*60)
    print(f"✓ Generated {len(keys)} private keys")
    print("="*60)


def main():
    print("="*60)
    print("PRIVATE KEY EXTRACTOR FROM MNEMONIC")
    print("="*60)
    print("\n⚠️  WARNING: Keep your mnemonic and private keys SECURE!")
    print("⚠️  Never share them or commit to git!\n")
    
    # Get mnemonic from user
    print("Enter your mnemonic phrase (12 or 24 words):")
    mnemonic_phrase = input().strip()
    
    if not mnemonic_phrase:
        print("❌ No mnemonic provided")
        sys.exit(1)
    
    print("\nDeriving keys...\n")
    
    try:
        keys = derive_keys_from_mnemonic(mnemonic_phrase)
        format_env_output(keys)
        
        print("\n💡 TIP: Some chains use the same key:")
        print("   - ETH key works for: BNB, MATIC, AVAX, USDT-ERC20, USDC-ERC20, USDT-BEP20")
        print("   - SOL key works for: USDT-SOL")
        print("   - TRX key works for: USDT-TRON")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()