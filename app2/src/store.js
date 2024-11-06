import { defineStore } from "pinia";
import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_AUTH_URL || "http://sso.local:5001",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Helper function to check cookies
const logCookies = (context) => {
  console.log(`=== Cookies Check (${context}) ===`);
  console.log("All cookies:", document.cookie);

  // Parse and display individual cookies
  const cookies = document.cookie.split(";").reduce((acc, cookie) => {
    const [key, value] = cookie.trim().split("=");
    acc[key] = value;
    return acc;
  }, {});

  console.log("Parsed cookies:", cookies);
  console.log("Specific access_token:", cookies["access_token"]);
  console.log("========================");
};

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`=== Request to ${config.url} ===`);
    console.log("Request headers:", config.headers);
    logCookies("Before Request");
    return config;
  },
  (error) => {
    console.error("Request error:", error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log(`=== Response from ${response.config.url} ===`);
    console.log("Response status:", response.status);
    console.log("Response headers:", response.headers);
    logCookies("After Response");

    // Check for Set-Cookie header
    const setCookie = response.headers["set-cookie"];
    if (setCookie) {
      console.log("Set-Cookie header found:", setCookie);
    } else {
      console.log("No Set-Cookie header in response");
    }

    return response;
  },
  (error) => {
    console.error("Response error:", error);
    return Promise.reject(error);
  }
);

export const useAuthStore = defineStore("auth", {
  state: () => ({
    user: null,
    token: null,
  }),

  actions: {
    async login(username, password) {
      try {
        console.log("=== Starting Login Process ===");
        logCookies("Before Login");

        const response = await api.post("/auth/login", {
          username,
          password,
        });

        console.log("Login response received:", response.data);
        this.token = response.data.token;
        this.user = response.data.user;

        logCookies("After Login");

        // Check response headers
        console.log("Response headers:", response.headers);
        console.log(
          "Access-Control-Expose-Headers:",
          response.headers["access-control-expose-headers"]
        );
        console.log("Set-Cookie header:", response.headers["set-cookie"]);

        return true;
      } catch (error) {
        console.error("Login error:", error);
        return false;
      }
    },

    async verify() {
      try {
        console.log("=== Starting Verify Process ===");
        logCookies("Before Verify");

        const response = await api.get("/auth/verify");
        console.log("Verify response:", response.data);

        logCookies("After Verify");

        if (response.data.authenticated) {
          this.user = response.data.user;
        }
        return response.data.authenticated;
      } catch (error) {
        console.error("Verify error:", error);
        return false;
      }
    },

    async logout() {
      try {
        console.log("=== Starting Logout Process ===");
        logCookies("Before Logout");

        const response = await api.post("/auth/logout");
        console.log("Logout response:", response.data);

        // Clear local state
        this.token = null;
        this.user = null;

        logCookies("After Logout");

        // You might want to redirect to login page here
        return true;
      } catch (error) {
        console.error("Logout error:", error);
        // Still clear local state even if the request fails
        this.token = null;
        this.user = null;
        throw error;
      }
    },
  },
});
