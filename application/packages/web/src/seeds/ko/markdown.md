---
id: 3d0c
title: markdown으로 여기서 할 수 있는 모든 것
---

아래에 있는 건 전부 이 노트 위쪽 도구 모음으로 만들었어요. 설정도, 플러그인도 없어요. 글자를 선택하면 도구 모음이 거기에 적용돼요. 빈 줄을 클릭하면 새로운 것이 시작돼요.

## 낱말

낱말을 **굵게** 하거나, *기울이거나*, ***둘 다*** 할 수 있어요. ~~이렇게~~ 줄을 그을 수도 있어요. <u>밑줄</u>도 그을 수 있어요. 작은 글씨는 <sub>아래 첨자</sub>로, 지수는 <sup>위 첨자</sup>로 가요.

글자는 <span style="color: #e03131">빨강</span>, <span style="color: #1971c2">파랑</span>, <span style="color: #2f9e44">초록</span>을 비롯해 아홉 가지 색이 돼요.

==노랑으로 강조==하거나 <mark style="background-color: rgba(64, 192, 87, 0.35)">초록으로</mark> 할 수 있어요.

**Aa** 버튼이 크기와 글꼴을 바꿔요. 글자는 <span style="font-size: 0.85em">작게</span>, 보통으로, <span style="font-size: 1.6em">크게</span> 할 수 있어요. <span style="font-family: ui-sans-serif, system-ui, sans-serif">고딕</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">명조</span>, <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">고정폭</span> 중에서 고를 수 있어요.

## 글자가 놓이는 자리

<p style="text-align: center;">이 문단은 가운데에 있어요.</p>

<p style="text-align: right;">이 문단은 오른쪽으로 밀려 있어요.</p>

정렬은 문단 전체를 옮겨요. 낱말 하나만 옮기지는 못해요. 문단에 커서를 두고 정렬 버튼을 쓰세요.

## 목록

- 평범한 항목
- 하나 더
  - Tab을 누르면 한 칸 들어가요
    - 한 번 더

1. 번호가 붙은 단계
2. 두 번째 단계
3. 중간에 단계를 넣어도 번호는 알아서 고쳐져요

- [x] 체크한 칸

- [ ] 체크 칸

  - [ ] Tab을 누르면 할 일이 한 칸 들어가요

  - [ ] 칸을 체크하고 움직임을 보세요

- [ ] Shift와 Tab을 누르면 들여쓰기가 줄어요

## 표

| 지역 | 노트 | 비중 |
| --- | :---: | ---: |
| 유럽 | 1,204 | 48% |
| 아메리카 | 902 | 36% |
| 아시아 | 401 | 16% |

가운데 열은 가운데 정렬, 마지막 열은 오른쪽 정렬이에요. 열 가장자리를 끌면 넓어져요.

## 콜아웃

콜아웃은 읽는 사람이 놓치면 안 되는 것을 담는 색 상자예요.

> [!tip]+ 팁
> 콜아웃 제목을 클릭하면 접혀요.

> [!warning]+ 주의
> 종류마다 색과 아이콘이 달라요.

> [!danger]+ 위험
> 아홉 가지가 있어요. **삽입** 메뉴에 목록이 있어요.

## 인용

> 인용은 여백에서 한 칸 들어오고 옆에 색 선이 붙어요.

## 코드

코드는 띄어쓰기를 그대로 두고 언어에 따라 색이 붙어요.

```js
export function seal(note, key) {
  const nonce = randomBytes(24);
  return xchacha20poly1305(key, nonce).encrypt(note);
}
```

```python
def rolling_mean(values, window):
    return [sum(values[i:i + window]) / window
            for i in range(len(values) - window + 1)]
```

문장 안의 짧은 코드는 이렇게 보여요: `이것`.

## 수식

수식은 문장 안에 들어갈 수도 있고($a^2 + b^2 = c^2$처럼), 한 줄을 차지할 수도 있어요.

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## 이미지

![벚꽃 너머로 보이는 후지산.](/onboarding/fuji.webp){width=50 align=center}

이미지를 노트로 끌어다 놓거나 붙여 넣으세요. 한 번 클릭하면 크기를 바꾸거나 왼쪽, 가운데, 오른쪽으로 옮길 수 있어요. 위 이미지는 절반 너비로 가운데에 놓았어요.

## 링크

두 종류가 있고, 일부러 다르게 보이게 했어요.

- 웹 링크는 사이트를 열어요: [privacynotes.app](https://privacynotes.app/ko)
- 노트 링크는 당신의 다른 노트를 열어요: [[노트가 어떻게 보호되나요]]

둘 다 도구 모음에 버튼이 있어요. 사슬이 웹 링크를 만들어요. 대괄호는 노트 링크를 만들어요. 노트 목록을 보여 주고, 거기서 원하는 노트를 고르면 돼요. `[[`를 입력해도 똑같아요.

---

*이미 markdown을 쓰고 있다면 그대로 치세요. 치는 대로 서식이 붙어요. 어떤 노트든 원래 글자를 보려면 이 노트 오른쪽 아래의 **markdown 보기**를 누르세요.*
