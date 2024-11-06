<template>
    <div class="home">
        <h1>Welcome to App 2</h1>
        <div class="user-info" v-if="authStore.user">
            <p>You are logged in as: {{ authStore.user.name }}</p>
            <div class="button-group">
                <button @click="openApp1" class="nav-btn">
                    Open App 1
                </button>
                <button @click="handleLogout" class="logout-btn">
                    Logout
                </button>
            </div>
        </div>
        <div v-else>
            <p>You are not logged in.</p>
        </div>
    </div>
</template>

<script setup>
import { useAuthStore } from '../store';
import { useRouter } from 'vue-router';

const authStore = useAuthStore();
const router = useRouter();

const handleLogout = async () => {
    try {
        await authStore.logout();
        router.push('/login');
    } catch (error) {
        console.error('Logout failed:', error);
    }
};

const openApp1 = () => {
    window.open('http://app1.sso.local:8080', '_blank');
};
</script>

<style scoped>
.home {
    text-align: center;
    padding: 2rem;
}

.user-info {
    margin-top: 1rem;
}

.button-group {
    display: flex;
    gap: 1rem;
    justify-content: center;
    margin-top: 1rem;
}

.nav-btn {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
    transition: background-color 0.3s;
}

.nav-btn:hover {
    background-color: #0056b3;
}

.nav-btn:focus {
    outline: none;
    box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.3);
}

.logout-btn {
    background-color: #dc3545;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
    transition: background-color 0.3s;
}

.logout-btn:hover {
    background-color: #c82333;
}

.logout-btn:focus {
    outline: none;
    box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.3);
}
</style>