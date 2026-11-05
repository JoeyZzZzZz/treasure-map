// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// The vtable / typeinfo decoy (a shared library): six polymorphic classes. Each typeinfo is
// {vtable symbol + 16, name}, emitted one after another, so read one word late the array is
// {name, imported vtable + 16} records — not a dispatch table. Synthetic names.
struct FxShape { virtual ~FxShape() {} virtual int area() const = 0; };
struct FxSquare : FxShape { int area() const override { return 4; } };
struct FxCircle : FxShape { int area() const override { return 3; } };
struct FxTriangle : FxShape { int area() const override { return 2; } };
struct FxHexagon : FxShape { int area() const override { return 6; } };
struct FxOctagon : FxShape { int area() const override { return 8; } };

extern "C" int fx_total(int which) {
    FxSquare s; FxCircle c; FxTriangle t; FxHexagon h; FxOctagon o;
    const FxShape *all[] = {&s, &c, &t, &h, &o};
    return all[which % 5]->area();
}
