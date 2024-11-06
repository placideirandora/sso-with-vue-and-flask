import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "./store";

const routes = [
  {
    path: "/",
    redirect: "/home",
  },
  {
    path: "/login",
    name: "login",
    component: () => import("./views/LoginView.vue"),
    meta: { guest: true },
  },
  {
    path: "/home",
    name: "home",
    component: () => import("./views/HomeView.vue"),
    meta: { requiresAuth: true },
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore();
  const isAuthenticated = await authStore.verify();

  if (to.meta.requiresAuth && !isAuthenticated) {
    next("/login");
  } else if (to.meta.guest && isAuthenticated) {
    next("/home");
  } else {
    next();
  }
});

export default router;
