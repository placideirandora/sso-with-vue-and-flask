<template>
    <nav class="nav">
        <div class="nav-brand">App 1</div>
        <div class="nav-items">
            <span>Welcome, {{ authStore.username }}!</span>
            <button @click="handleLogout">Logout</button>
            <button v-if="isApp1" @click="openApp2">Open App 2</button>
        </div>
    </nav>
</template>

<script setup>
import { useAuthStore } from '../store'
import { useRouter } from 'vue-router'

const authStore = useAuthStore()
const router = useRouter()

const isApp1 = window.location.pathname.includes('app1')

const handleLogout = async () => {
    await authStore.logout()
    router.push('/login')
}

const openApp2 = () => {
    window.open('http://localhost/app2', '_blank')
}
</script>

<style scoped>
.nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background-color: #f8f9fa;
    margin-bottom: 2rem;
}

.nav-items {
    display: flex;
    gap: 1rem;
    align-items: center;
}

button {
    padding: 0.5rem 1rem;
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

button:hover {
    background-color: #0056b3;
}
</style>
