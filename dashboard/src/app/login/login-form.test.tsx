import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";

import { server } from "@/test/server";
import { stubNavigation } from "@/test/utils";
import { LoginForm } from "./login-form";

const LOGIN = "http://localhost:3000/api/auth/login";

async function signIn(password = "secret-password") {
  await userEvent.type(screen.getByLabelText("Username"), "chinmay");
  await userEvent.type(screen.getByLabelText("Password"), password);
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("Login", () => {
  let nav: ReturnType<typeof stubNavigation> | undefined;
  afterEach(() => nav?.restore());

  it("signs in and goes to the overview", async () => {
    nav = stubNavigation();
    server.use(http.post(LOGIN, () => HttpResponse.json({ username: "chinmay" })));
    render(<LoginForm />);
    await signIn();
    await waitFor(() => expect(nav!.assign).toHaveBeenCalledWith("/"));
  });

  it("says plainly when the password is wrong", async () => {
    server.use(http.post(LOGIN, () => HttpResponse.json({ detail: "x" }, { status: 401 })));
    render(<LoginForm />);
    await signIn("nope");
    expect(await screen.findByRole("alert")).toHaveTextContent("Wrong username or password.");
  });

  it("explains a lockout after too many attempts", async () => {
    server.use(http.post(LOGIN, () => HttpResponse.json({ detail: "x" }, { status: 429 })));
    render(<LoginForm />);
    await signIn();
    expect(await screen.findByRole("alert")).toHaveTextContent("Wait 15 minutes");
  });

  it("never redirects to another site after login", async () => {
    nav = stubNavigation();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...window.location, search: "?next=//evil.example" },
    });
    server.use(http.post(LOGIN, () => HttpResponse.json({ username: "chinmay" })));
    render(<LoginForm />);
    await signIn();
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledWith("/"));
  });
});
