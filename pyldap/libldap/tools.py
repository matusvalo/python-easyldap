def iterate_array(arr, f=None):
    i = 0
    while True:
        if not arr[i]:
            break
        yield arr[i] if f is None else f(arr[i])
        i += 1