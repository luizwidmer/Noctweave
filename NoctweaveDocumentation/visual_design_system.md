# Noctweave Visual Design System

Noctweave applications use one visual language across native and web surfaces. Product layouts may differ, but color roles, spacing, control behavior, and accessibility expectations remain consistent.

## Brand Palette

| Role | Dark | Light |
| --- | --- | --- |
| Canvas | `#120B0F` | `#FAF6F2` |
| Background | `#1B1217` | `#FAF3EA` |
| Raised surface | `#2A1B21` | `#FFFDFB` |
| Field surface | `#170F13` | `#F7EEE9` |
| Primary text | `#FAF3EA` | `#25191E` |
| Secondary text | `#BDA9AA` | `#765F64` |
| Border | `#56313A` | `#D9C6C1` |
| Accent | `#C96A61` | `#A84F4B` |
| Accent strong | `#B55250` | `#8E3F43` |
| Success | `#79C6A3` | `#2F7D60` |
| Warning | `#E3A85D` | `#8A571D` |
| Danger | `#FF7888` | `#B23A4D` |

The Offset Veil mark keeps its ivory (`#FAF3EA`) and coral (`#C96A61`) fills in both modes.

## Semantic Rules

- Use semantic roles rather than fixed black, white, or opacity values.
- Light mode changes canvas, surfaces, fields, borders, text, and shadows—not only accent color.
- Dark mode uses restrained coral/wine glows. Light mode uses warm ivory surfaces and low-opacity coral shadows.
- Application chrome uses Noctweave colors. User-authored website content may define its own accent.
- System is the default appearance. Explicit Light and Dark choices persist locally.

## Components

- Cards: 14–22 pt continuous radius, one semantic border, and a soft elevation shadow.
- Inputs: at least 42 pt high with a visible focus ring and no separate dark wrapper.
- Buttons: 11–13 pt radius; hover increases border/accent glow without changing the control shape.
- Navigation: selected items use an accent-soft fill and high-contrast text; inactive items use secondary text.
- Status: use color plus text or an icon. Never communicate state through color alone.
- Empty states: one clear title, one sentence, and at most one primary action.

## Layout and Motion

Use an 8 pt spacing rhythm with 12, 16, 24, and 32 pt content intervals. Keep readable content bounded on wide windows and preserve safe-area padding on compact screens. Hover, press, and selection transitions should complete within 120–200 ms and respect Reduce Motion.

## Accessibility

All interactive elements need keyboard focus indicators, descriptive labels, and a minimum 44×44 pt touch target on iOS. Verify primary text and controls at WCAG AA contrast in both modes. Do not reduce privacy protections, redaction behavior, or secure-container coverage for visual consistency.
