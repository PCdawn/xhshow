"""x-s-common signature generation"""

import hashlib
import json
from typing import Any

from ..config import CryptoConfig
from ..core.crc32_encrypt import CRC32
from ..utils.encoder import Base64Encoder

__all__ = ["XsCommonSigner"]


class XsCommonSigner:
    """Generate x-s-common signatures"""

    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self._encoder = Base64Encoder(self.config)

    def sign(self, cookie_dict: dict[str, Any], xs: str = "", xt: int | str | None = None) -> str:
        """
        Generate x-s-common signature

        Args:
            cookie_dict: Cookie dictionary (must be dict, not string)
            xs: x-s signature value (recommended: full XYS_ string)
            xt: x-t value in milliseconds

        Returns:
            x-s-common signature string

        Raises:
            KeyError: If 'a1' cookie is missing
        """
        a1_value = cookie_dict["a1"]
        if xt is None:
            xt = 0
        xt_int = int(xt)
        x8 = self.config.XSCOMMON_X8_STATIC
        # MD5 here is required only for protocol compatibility with upstream x-s-common.
        md5_hex = hashlib.md5(f"{xt_int}{xs}{x8}".encode()).hexdigest()
        x9 = CRC32.crc32_js_int(bytes.fromhex(md5_hex))

        sign_struct = dict(self.config.SIGNATURE_XSCOMMON_TEMPLATE)
        sign_struct["x5"] = a1_value
        sign_struct["x6"] = xt_int
        sign_struct["x7"] = xs
        sign_struct["x8"] = x8
        sign_struct["x9"] = x9

        sign_json = json.dumps(sign_struct, separators=(",", ":"), ensure_ascii=False)
        xs_common = self._encoder.encode(sign_json)

        return xs_common
