"""Render the end-to-end auth and tool-call sequence diagram for the README.

Draws two phases across seven lanes: the RFC 8628 device-grant flow the
customer uses to authorize the AI client, and a tool call travelling from
the AI client through Postern to a domain service behind Istio.

Regenerate with:

    uv run --with pillow python tools/render_auth_flow.py

Output: docs/images/auth-flow.png
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Canvas is authored at 2x the final pixel size, then downsampled with
# LANCZOS so the text and lines are crisp at normal README width.
# ---------------------------------------------------------------------------

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "docs" / "images" / "auth-flow.png"

FONT_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)

BG = "#FCFCFA"
INK = "#1C2430"
LANE_LINE = "#B7BEC9"
BOX_FILL = "#FFFFFF"
BOX_BORDER = "#3B4A63"
BAND_FILL = "#E4E9F2"
BAND_TEXT = "#1C2430"
ACCENT = "#B00020"

LANE_NAMES = [
    "AI client",
    "Browser",
    "Postern API",
    "Bank app",
    "Confirmation svc",
    "Vault",
    "Istio ingress → domain services",
]

MARGIN_X = 260
LANE_SPACING = 500
CANVAS_WIDTH = MARGIN_X * 2 + LANE_SPACING * (len(LANE_NAMES) - 1)

HEADER_TOP = 50
HEADER_FONT_SIZE = 30
HEADER_LINE_HEIGHT = 40
HEADER_PAD = 24
HEADER_BOX_WIDTH = 400

LABEL_FONT_SIZE = 26
LINE_HEIGHT = 38
NUMBER_FONT_SIZE = 26

ROW_TOP_PAD = 22
ARROW_GAP = 16
ROW_BOTTOM_PAD = 34

LOOP_WIDTH = 150
LOOP_DEPTH = 70

CALL_LABEL_PADDING = 100
SELF_SIDE_MARGIN = 20
SELF_LABEL_MAX_WIDTH = 430

PHASE_BAND_HEIGHT = 90
PHASE_FONT_SIZE = 32
GAP_HEADER_TO_BAND = 30
GAP_BAND_TO_STEPS = 34
GAP_BETWEEN_PHASES = 30
GAP_TO_LEGEND = 60
LEGEND_HEIGHT = 70
BOTTOM_MARGIN = 40

ARROW_WIDTH_NORMAL = 4
ARROW_WIDTH_ACCENT = 7
ARROWHEAD_LEN_NORMAL = 22
ARROWHEAD_LEN_ACCENT = 26
ARROWHEAD_HALF_WIDTH_NORMAL = 9
ARROWHEAD_HALF_WIDTH_ACCENT = 11

SCALE_FOR_RESAMPLE = 2

LEGEND_TEXT = (
    "Accent = the three steps the whole security design rests on: pairing-code "
    "confirmation, internal JWT minting, and the domain service enforcing on sub."
)


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load the first available TrueType font at the given pixel size."""
    for path in FONT_CANDIDATES:
        if Path(path).is_file():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


HEADER_FONT = load_font(HEADER_FONT_SIZE)
LABEL_FONT = load_font(LABEL_FONT_SIZE)
PHASE_FONT = load_font(PHASE_FONT_SIZE)
LEGEND_FONT = load_font(28)


def wrap_text(
    text: str, font: ImageFont.FreeTypeFont | ImageFont.ImageFont, max_width: float
) -> list[str]:
    """Word-wrap text so no line exceeds max_width when rendered in font."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        width = font.getbbox(candidate)[2]
        if width <= max_width or not current:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


Kind = Literal["call", "self"]


@dataclass(frozen=True)
class Step:
    number: int
    kind: Kind
    src: int
    dst: int
    label: str
    highlight: bool = False


PHASE_A_TITLE = "A. Customer authorizes the client (RFC 8628 device grant)"
PHASE_B_TITLE = "B. A tool call reaches a domain service"

PHASE_A_STEPS: list[Step] = [
    Step(1, "call", 0, 2, "GET /authorize (PKCE)"),
    Step(
        2,
        "self",
        2,
        2,
        "INSERT challenge: device_code, user_code, scopes, 2 to 5 min TTL",
    ),
    Step(3, "call", 2, 1, "rotating QR + pairing code + universal link"),
    Step(
        4,
        "call",
        1,
        3,
        "user scans QR (desktop) or universal link opens the app (mobile)",
    ),
    Step(5, "self", 3, 3, "shows pairing code, client name, requested scopes"),
    Step(
        6,
        "self",
        3,
        3,
        "user confirms the pairing code MATCHES the browser",
        highlight=True,
    ),
    Step(
        7,
        "call",
        3,
        4,
        "app identity verification, server-side selfie match (tier 2 only)",
    ),
    Step(8, "self", 3, 3, "device-bound key signs the challenge payload"),
    Step(9, "call", 3, 4, "signed approval"),
    Step(10, "call", 4, 2, "approval: signature + device id"),
    Step(11, "call", 0, 2, "POST /token (device_code, PKCE verifier), polled"),
    Step(12, "call", 2, 0, "customer access token"),
]

PHASE_B_STEPS: list[Step] = [
    Step(13, "call", 0, 2, "tools/call accounts.list, Bearer customer token"),
    Step(14, "self", 2, 2, "JWTVerifier checks jwks_uri, issuer, audience"),
    Step(
        15,
        "call",
        5,
        2,
        "READ signing key, fetched at startup via AWS IAM auth, cached",
    ),
    Step(
        16,
        "self",
        2,
        2,
        "mints internal JWT locally: RS256, 60s, sub=cust ref, act=svc:postern, aud=accounts.svc",
        highlight=True,
    ),
    Step(17, "call", 2, 6, "GET /accounts, Bearer internal JWT"),
    Step(
        18,
        "self",
        6,
        6,
        "RequestAuthentication validates against Postern JWKS; AuthorizationPolicy "
        "checks issuer (read vs write)",
    ),
    Step(
        19,
        "self",
        6,
        6,
        "forwardOriginalToken; the domain service enforces on sub",
        highlight=True,
    ),
    Step(20, "call", 6, 2, "rows"),
    Step(
        21,
        "call",
        2,
        0,
        "projected and masked result: refs, masked IBAN, no counterparty account",
    ),
]


@dataclass
class RowLayout:
    step: Step
    lines: list[str]
    top: int
    arrow_y: int
    height: int


@dataclass
class Diagram:
    lane_x: list[int] = field(default_factory=list)
    header_bottom: int = 0
    phase_a_band_top: int = 0
    phase_a_band_bottom: int = 0
    phase_a_rows: list[RowLayout] = field(default_factory=list)
    phase_b_band_top: int = 0
    phase_b_band_bottom: int = 0
    phase_b_rows: list[RowLayout] = field(default_factory=list)
    lifeline_bottom: int = 0
    legend_y: int = 0
    total_height: int = 0


def self_call_flip(step: Step) -> bool:
    """Whether a self-call loop bulges left instead of the default right.

    Only the rightmost lane flips, so its loop and label stay on-canvas
    instead of running off the right edge.
    """
    return step.src == len(LANE_NAMES) - 1


def label_geometry(step: Step, lane_x: list[int]) -> tuple[int, float]:
    """Return (center_x, max_width) for a step's wrapped label block."""
    if step.kind == "self":
        half = SELF_LABEL_MAX_WIDTH / 2
        if self_call_flip(step):
            center_x = int(lane_x[step.src] - SELF_SIDE_MARGIN - half)
        else:
            center_x = int(lane_x[step.src] + SELF_SIDE_MARGIN + half)
        return center_x, float(SELF_LABEL_MAX_WIDTH)
    span = abs(lane_x[step.dst] - lane_x[step.src])
    center_x = (lane_x[step.src] + lane_x[step.dst]) // 2
    max_width = max(span - CALL_LABEL_PADDING, 240)
    return center_x, float(max_width)


def build_rows(steps: list[Step], lane_x: list[int], start_top: int) -> list[RowLayout]:
    rows: list[RowLayout] = []
    top = start_top
    for step in steps:
        _, max_width = label_geometry(step, lane_x)
        text = f"{step.number}. {step.label}"
        lines = wrap_text(text, LABEL_FONT, max_width)
        label_block_height = len(lines) * LINE_HEIGHT
        arrow_y = top + ROW_TOP_PAD + label_block_height + ARROW_GAP
        if step.kind == "self":
            height = ROW_TOP_PAD + label_block_height + ARROW_GAP + LOOP_DEPTH + ROW_BOTTOM_PAD
        else:
            height = ROW_TOP_PAD + label_block_height + ARROW_GAP + ROW_BOTTOM_PAD
        rows.append(RowLayout(step=step, lines=lines, top=top, arrow_y=arrow_y, height=height))
        top += height
    return rows


def compute_layout() -> Diagram:
    diagram = Diagram()
    diagram.lane_x = [MARGIN_X + i * LANE_SPACING for i in range(len(LANE_NAMES))]

    header_line_counts = [
        len(wrap_text(name, HEADER_FONT, HEADER_BOX_WIDTH - 2 * HEADER_PAD)) for name in LANE_NAMES
    ]
    header_box_height = HEADER_PAD * 2 + max(header_line_counts) * HEADER_LINE_HEIGHT
    diagram.header_bottom = HEADER_TOP + header_box_height

    diagram.phase_a_band_top = diagram.header_bottom + GAP_HEADER_TO_BAND
    diagram.phase_a_band_bottom = diagram.phase_a_band_top + PHASE_BAND_HEIGHT

    steps_a_top = diagram.phase_a_band_bottom + GAP_BAND_TO_STEPS
    diagram.phase_a_rows = build_rows(PHASE_A_STEPS, diagram.lane_x, steps_a_top)
    phase_a_bottom = diagram.phase_a_rows[-1].top + diagram.phase_a_rows[-1].height

    diagram.phase_b_band_top = phase_a_bottom + GAP_BETWEEN_PHASES
    diagram.phase_b_band_bottom = diagram.phase_b_band_top + PHASE_BAND_HEIGHT

    steps_b_top = diagram.phase_b_band_bottom + GAP_BAND_TO_STEPS
    diagram.phase_b_rows = build_rows(PHASE_B_STEPS, diagram.lane_x, steps_b_top)
    phase_b_bottom = diagram.phase_b_rows[-1].top + diagram.phase_b_rows[-1].height

    diagram.lifeline_bottom = phase_b_bottom
    diagram.legend_y = diagram.lifeline_bottom + GAP_TO_LEGEND
    diagram.total_height = diagram.legend_y + LEGEND_HEIGHT + BOTTOM_MARGIN
    return diagram


def draw_lifelines(draw: ImageDraw.ImageDraw, diagram: Diagram) -> None:
    dash, gap = 10, 8
    for x in diagram.lane_x:
        y = diagram.header_bottom
        while y < diagram.lifeline_bottom:
            y_end = min(y + dash, diagram.lifeline_bottom)
            draw.line([(x, y), (x, y_end)], fill=LANE_LINE, width=2)
            y += dash + gap


def draw_headers(draw: ImageDraw.ImageDraw, diagram: Diagram) -> None:
    header_line_counts = [
        wrap_text(name, HEADER_FONT, HEADER_BOX_WIDTH - 2 * HEADER_PAD) for name in LANE_NAMES
    ]
    box_height = HEADER_PAD * 2 + max(len(lines) for lines in header_line_counts) * (
        HEADER_LINE_HEIGHT
    )
    for x, lines in zip(diagram.lane_x, header_line_counts, strict=True):
        left = x - HEADER_BOX_WIDTH // 2
        right = x + HEADER_BOX_WIDTH // 2
        top = HEADER_TOP
        bottom = top + box_height
        draw.rectangle([left, top, right, bottom], fill=BOX_FILL, outline=BOX_BORDER, width=3)
        block_height = len(lines) * HEADER_LINE_HEIGHT
        text_top = top + (box_height - block_height) // 2
        for i, line in enumerate(lines):
            w = HEADER_FONT.getbbox(line)[2]
            draw.text(
                (x - w / 2, text_top + i * HEADER_LINE_HEIGHT),
                line,
                font=HEADER_FONT,
                fill=INK,
                stroke_width=1,
            )


def draw_phase_band(draw: ImageDraw.ImageDraw, top: int, bottom: int, title: str) -> None:
    draw.rectangle([0, top, CANVAS_WIDTH, bottom], fill=BAND_FILL)
    draw.line([(0, top), (CANVAS_WIDTH, top)], fill=BOX_BORDER, width=2)
    draw.line([(0, bottom), (CANVAS_WIDTH, bottom)], fill=BOX_BORDER, width=2)
    w = PHASE_FONT.getbbox(title)[2]
    y = top + (bottom - top - PHASE_FONT_SIZE) // 2 - 4
    draw.text((CANVAS_WIDTH / 2 - w / 2, y), title, font=PHASE_FONT, fill=BAND_TEXT, stroke_width=1)


def arrowhead(
    tip_x: int, tip_y: int, pointing_right: bool, length: int, half_width: int
) -> list[tuple[int, int]]:
    """Triangle polygon for an arrowhead whose tip sits at (tip_x, tip_y)."""
    if pointing_right:
        back_x = tip_x - length
    else:
        back_x = tip_x + length
    return [
        (tip_x, tip_y),
        (back_x, tip_y - half_width),
        (back_x, tip_y + half_width),
    ]


def draw_label_block(
    draw: ImageDraw.ImageDraw, lines: list[str], center_x: int, top: int, color: str, bold: bool
) -> None:
    for i, line in enumerate(lines):
        w = LABEL_FONT.getbbox(line)[2]
        draw.text(
            (center_x - w / 2, top + i * LINE_HEIGHT),
            line,
            font=LABEL_FONT,
            fill=color,
            stroke_width=1 if bold else 0,
        )


def draw_call(draw: ImageDraw.ImageDraw, row: RowLayout, lane_x: list[int]) -> None:
    step = row.step
    color = ACCENT if step.highlight else INK
    width = ARROW_WIDTH_ACCENT if step.highlight else ARROW_WIDTH_NORMAL
    head_len = ARROWHEAD_LEN_ACCENT if step.highlight else ARROWHEAD_LEN_NORMAL
    half_w = ARROWHEAD_HALF_WIDTH_ACCENT if step.highlight else ARROWHEAD_HALF_WIDTH_NORMAL

    x_src = lane_x[step.src]
    x_dst = lane_x[step.dst]
    y = row.arrow_y
    pointing_right = x_dst > x_src

    draw.line([(x_src, y), (x_dst, y)], fill=color, width=width)
    draw.polygon(arrowhead(x_dst, y, pointing_right, head_len, half_w), fill=color)

    center_x, _ = label_geometry(step, lane_x)
    label_top = row.top + ROW_TOP_PAD
    draw_label_block(draw, row.lines, center_x, label_top, color, step.highlight)


def draw_self_call(draw: ImageDraw.ImageDraw, row: RowLayout, lane_x: list[int]) -> None:
    step = row.step
    color = ACCENT if step.highlight else INK
    width = ARROW_WIDTH_ACCENT if step.highlight else ARROW_WIDTH_NORMAL
    head_len = ARROWHEAD_LEN_ACCENT if step.highlight else ARROWHEAD_LEN_NORMAL
    half_w = ARROWHEAD_HALF_WIDTH_ACCENT if step.highlight else ARROWHEAD_HALF_WIDTH_NORMAL

    x = lane_x[step.src]
    y_top = row.arrow_y
    y_bottom = y_top + LOOP_DEPTH
    flip = self_call_flip(step)
    x_out = x - LOOP_WIDTH if flip else x + LOOP_WIDTH

    draw.line([(x, y_top), (x_out, y_top)], fill=color, width=width)
    draw.line([(x_out, y_top), (x_out, y_bottom)], fill=color, width=width)
    draw.line([(x_out, y_bottom), (x, y_bottom)], fill=color, width=width)
    draw.polygon(arrowhead(x, y_bottom, flip, head_len, half_w), fill=color)

    center_x, _ = label_geometry(step, lane_x)
    label_top = row.top + ROW_TOP_PAD
    draw_label_block(draw, row.lines, center_x, label_top, color, step.highlight)


def draw_steps(draw: ImageDraw.ImageDraw, rows: list[RowLayout], lane_x: list[int]) -> None:
    for row in rows:
        if row.step.kind == "self":
            draw_self_call(draw, row, lane_x)
        else:
            draw_call(draw, row, lane_x)


def draw_legend(draw: ImageDraw.ImageDraw, y: int) -> None:
    swatch = 26
    draw.rectangle([MARGIN_X, y, MARGIN_X + swatch, y + swatch], fill=ACCENT)
    lines = wrap_text(LEGEND_TEXT, LEGEND_FONT, CANVAS_WIDTH - 2 * MARGIN_X - swatch - 20)
    for i, line in enumerate(lines):
        draw.text(
            (MARGIN_X + swatch + 20, y + i * 34),
            line,
            font=LEGEND_FONT,
            fill=INK,
        )


def render() -> Image.Image:
    diagram = compute_layout()
    image = Image.new("RGB", (CANVAS_WIDTH, diagram.total_height), BG)
    draw = ImageDraw.Draw(image)

    draw_lifelines(draw, diagram)
    draw_phase_band(draw, diagram.phase_a_band_top, diagram.phase_a_band_bottom, PHASE_A_TITLE)
    draw_phase_band(draw, diagram.phase_b_band_top, diagram.phase_b_band_bottom, PHASE_B_TITLE)
    draw_steps(draw, diagram.phase_a_rows, diagram.lane_x)
    draw_steps(draw, diagram.phase_b_rows, diagram.lane_x)
    draw_headers(draw, diagram)
    draw_legend(draw, diagram.legend_y)

    final_size = (
        CANVAS_WIDTH // SCALE_FOR_RESAMPLE,
        diagram.total_height // SCALE_FOR_RESAMPLE,
    )
    return image.resize(final_size, Image.LANCZOS)


def main() -> None:
    image = render()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT_PATH)
    print(f"wrote {OUTPUT_PATH} ({image.width}x{image.height})")


if __name__ == "__main__":
    main()
