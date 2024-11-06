<template>
    <div id="app">
        <router-view v-if="initialized"></router-view>
        <div v-else>Loading...</div>
    </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useAuthStore } from './store'
import { useRouter } from 'vue-router'

const router = useRouter()
const authStore = useAuthStore()
const initialized = ref(false)

onMounted(async () => {
    try {
        // Check authentication status on app load
        const isAuthenticated = await authStore.verify()
        if (isAuthenticated) {
            if (router.currentRoute.value.name === 'login') {
                router.push('/home')
            }
        } else if (router.currentRoute.value.meta.requiresAuth) {
            router.push('/login')
        }
    } catch (error) {
        console.error('Auth initialization error:', error)
    } finally {
        initialized.value = true
    }
})
</script>