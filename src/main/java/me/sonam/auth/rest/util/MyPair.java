package me.sonam.auth.rest.util;
import java.util.Objects;

public class MyPair<K, V> {
    private K key;
    private V value;

    public MyPair(K key, V value) {
        this.key = key;
        this.value = value;
    }

    public MyPair() {
    }

    public K getKey() {
        return key;
    }

    public void setKey(K key) {
        this.key = key;
    }

    public V getValue() {
        return value;
    }

    public void setValue(V value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return "MyPair{" +
                "k=" + key +
                ", v=" + value +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MyPair<?, ?> myPair = (MyPair<?, ?>) o;
        return Objects.equals(key, myPair.key) && Objects.equals(value, myPair.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key, value);
    }
}
