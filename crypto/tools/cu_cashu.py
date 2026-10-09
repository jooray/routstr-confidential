#!/usr/bin/env python3
"""Test Cashu helper for the confidential-upstream e2e.

Thin wrapper around the ``cashu`` wallet library, used to *drive* the test
mint (mint an escrow token for the reference client) and to *verify* money the
node produced (redeem a returned refund token and report its amount). It is a
test tool, not part of the protocol.

Run it in an ephemeral environment so nothing is installed globally:

    uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
        crypto/tools/cu_cashu.py mint --mint http://127.0.0.1:3338 --sats 20

Subcommands:

    mint    --mint URL --sats N            mint N sats, print the token
    balance --mint URL                     print the wallet balance
    redeem  --token TOKEN                  redeem a token, print amount redeemed
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from cashu.core.base import MintQuoteState, TokenV4
from cashu.wallet.wallet import Wallet


def _wallet_name(mint_url: str) -> str:
    return f"cu-e2e-{abs(hash(mint_url)) % 100000}"


async def _open(mint_url: str) -> Wallet:
    wallet = await Wallet.with_db(
        url=mint_url,
        db="wallet.sqlite3",
        name=_wallet_name(mint_url),
    )
    await wallet.load_mint()
    return wallet


async def _mint(mint_url: str, sats: int) -> str:
    wallet = await _open(mint_url)
    quote = await wallet.request_mint(sats)
    state = None
    for _ in range(50):
        refreshed = await wallet.get_mint_quote(quote.quote)
        state = refreshed.state
        if state in (MintQuoteState.paid, MintQuoteState.issued):
            break
        await asyncio.sleep(0.2)
    if state not in (MintQuoteState.paid, MintQuoteState.issued):
        raise SystemExit(f"mint quote never paid (state={state})")
    proofs = await wallet.mint(sats, quote.quote)
    token = await wallet.serialize_proofs(proofs, include_dleq=False, legacy=False)
    return token if isinstance(token, str) else str(token)


async def _balance(mint_url: str) -> int:
    wallet = await _open(mint_url)
    return int(wallet.available_balance.amount)


async def _redeem(token: str) -> dict:
    token_obj = TokenV4.deserialize(token)
    wallet = await _open(token_obj.mint)
    proofs = token_obj.proofs
    try:
        await wallet._expand_short_keyset_ids(proofs)
    except Exception:
        pass
    amount = sum(int(p.amount) for p in proofs)
    await wallet.redeem(proofs)
    return {"redeemed_sats": amount, "mint": token_obj.mint}


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--mint", required=True)
    m.add_argument("--sats", type=int, required=True)
    b = sub.add_parser("balance")
    b.add_argument("--mint", required=True)
    r = sub.add_parser("redeem")
    r.add_argument("--token", required=True)
    args = ap.parse_args()

    if args.cmd == "mint":
        print(asyncio.run(_mint(args.mint, args.sats)))
    elif args.cmd == "balance":
        print(asyncio.run(_balance(args.mint)))
    elif args.cmd == "redeem":
        print(json.dumps(asyncio.run(_redeem(args.token))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
