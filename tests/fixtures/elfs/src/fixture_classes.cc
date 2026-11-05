// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// The vtable / typeinfo decoy (a shared library): six polymorphic classes with no base class, each
// with an out-of-line virtual function so its vtable and typeinfo are emitted here. The typeinfo of
// a class with no base is two words, {imported class-type vtable + 16, name}, and the six are
// emitted one after another, so read one word late the array is a run of {name, imported vtable +
// 16} records at the pointer stride — the shape of a dispatch table whose handler is not a
// function. Synthetic names.
struct FxSquare { virtual ~FxSquare(); virtual int area() const; };
struct FxCircle { virtual ~FxCircle(); virtual int area() const; };
struct FxTriangle { virtual ~FxTriangle(); virtual int area() const; };
struct FxHexagon { virtual ~FxHexagon(); virtual int area() const; };
struct FxOctagon { virtual ~FxOctagon(); virtual int area() const; };
struct FxPentagon { virtual ~FxPentagon(); virtual int area() const; };

FxSquare::~FxSquare() {}
int FxSquare::area() const { return 4; }
FxCircle::~FxCircle() {}
int FxCircle::area() const { return 3; }
FxTriangle::~FxTriangle() {}
int FxTriangle::area() const { return 2; }
FxHexagon::~FxHexagon() {}
int FxHexagon::area() const { return 6; }
FxOctagon::~FxOctagon() {}
int FxOctagon::area() const { return 8; }
FxPentagon::~FxPentagon() {}
int FxPentagon::area() const { return 5; }

extern "C" int fx_total(const FxSquare *s, const FxCircle *c) {
    return s->area() + c->area();
}
