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

// Helper function to clear auth cookie
const clearAuthCookie = () => {
  document.cookie = `access_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=${
    import.meta.env.VITE_COOKIE_DOMAIN || ".sso.local"
  }`;
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

    return response;
  },
  (error) => {
    // Handle 401 responses
    if (error.response && error.response.status === 401) {
      // Clear local auth state
      const authStore = useAuthStore();
      authStore.clearAuth();
    }
    return Promise.reject(error);
  }
);

export const useAuthStore = defineStore("auth", {
  state: () => ({
    user: null,
  }),

  actions: {
    async login(email, password) {
      try {
        console.log("=== Starting Login Process ===");
        logCookies("Before Login");

        const response = await api.post("/auth/login", {
          email,
          password,
        });

        console.log("Login response received:", response.data);
        this.user = response.data.user;

        logCookies("After Login");
        return true;
      } catch (error) {
        console.error("Login error:", error);
        this.clearAuth();
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
          return true;
        }
        return false;
      } catch (error) {
        console.error("Verify error:", error);
        this.clearAuth();
        return false;
      }
    },

    async logout() {
      try {
        console.log("=== Starting Logout Process ===");
        logCookies("Before Logout");

        await api.post("/auth/logout");
        this.clearAuth();

        // Force clear the cookie on the client side as well
        clearAuthCookie();

        logCookies("After Logout");
        return true;
      } catch (error) {
        console.error("Logout error:", error);
        // Still clear auth state even if the request fails
        this.clearAuth();
        clearAuthCookie();
        throw error;
      }
    },

    clearAuth() {
      this.user = null;
    },
  },
});
