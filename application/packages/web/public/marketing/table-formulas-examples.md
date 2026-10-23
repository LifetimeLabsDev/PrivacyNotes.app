---
title: Table formulas
tags: formulas
---

Type `=` in any table cell to pick a function, or just write the formula yourself. The cell shows the answer, and your note keeps the formula: open this file in any other Markdown app and you will see `=SUM(D2:D4)`, exactly as it was typed.

Click any answer below to see the formula behind it. Click away and the answer comes back.

## A worked example

Change a quantity and watch the whole column follow.

| Item | Qty | Price | Line total |
| --- | --- | --- | --- |
| Desk | 2 | 249.50 | =B2*C2 |
| Chair | 4 | 89 | =B3*C3 |
| Lamp | 3 | 25 | =B4*C4 |
| | | Subtotal | =SUM(D2:D4) |
| | | VAT 20% | =D5*0.2 |
| | | Due | =D5+D6 |

Cells are named by column letter and row number. The header is row 1, so the first row of data is row 2.

## Every function

| Function | What it does | Written as | Answer |
| --- | --- | --- | --- |
| SUM | Add up values | `=SUM(10, 20, 30)` | =SUM(10, 20, 30) |
| PRODUCT | Multiply values | `=PRODUCT(2, 3, 4)` | =PRODUCT(2, 3, 4) |
| AVG | Average of values | `=AVG(4, 8, 9)` | =AVG(4, 8, 9) |
| MEDIAN | Middle value | `=MEDIAN(1, 5, 9)` | =MEDIAN(1, 5, 9) |
| MIN | Smallest value | `=MIN(4, 8, 2)` | =MIN(4, 8, 2) |
| MAX | Largest value | `=MAX(4, 8, 2)` | =MAX(4, 8, 2) |
| COUNT | How many numbers | `=COUNT(1, 2, 3)` | =COUNT(1, 2, 3) |
| ABS | Value without its sign | `=ABS(-7)` | =ABS(-7) |
| SQRT | Square root | `=SQRT(81)` | =SQRT(81) |
| SIGN | Positive or negative | `=SIGN(-3)` | =SIGN(-3) |
| CEIL | Round up | `=CEIL(1.2)` | =CEIL(1.2) |
| FLOOR | Round down | `=FLOOR(1.7)` | =FLOOR(1.7) |
| ROUND | Round to a whole number | `=ROUND(2.5)` | =ROUND(2.5) |
| ROUND | Round to decimals | `=ROUND(1.2345, 2)` | =ROUND(1.2345, 2) |
| LOG | Logarithm, base 10 | `=LOG(100)` | =LOG(100) |
| LOG | Logarithm, any base | `=LOG(8, 2)` | =LOG(8, 2) |
| RAND | A random number | `=RAND()` | =RAND() |
| PI | The constant pi | `=PI` | =PI |
| E | Euler's number | `=E` | =E |
| TAU | The constant tau | `=TAU` | =TAU |
| PHI | The golden ratio | `=PHI` | =PHI |

## Arithmetic

The four operators and brackets work anywhere, which is how you get a difference or a percentage.

| Written as | Answer |
| --- | --- |
| `=(2+3)*4` | =(2+3)*4 |
| `=100-37` | =100-37 |
| `=250/4` | =250/4 |
| `=SUM(10, 20, 30)/3` | =SUM(10, 20, 30)/3 |

## Three things worth knowing

- A range can point at cells that are themselves formulas, so a subtotal and a tax row stack up correctly.
- A range that covers its own cell skips itself, so `=SUM(B2:B99)` keeps working as you add rows.
- A formula that cannot be worked out shows itself, so you can see what needs fixing.
