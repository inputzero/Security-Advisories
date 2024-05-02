### Summary 

While performing the code review for `llm.c` in the below code snippet if `calloc` fails due to insufficient memory or any other reasons, it will return NULL. If either allocation fails, the code attempt to dereference a NULL pointer.

### Code Snippet

```C
// lazily allocate the memory for m_memory and v_memory
if (model->m_memory == NULL) {
        model->m_memory = (float*)calloc(model->num_parameters, sizeof(float));
        model->v_memory = (float*)calloc(model->num_parameters, sizeof(float));
```

### Fix

The ideal way is `calloc` should check or successfully allocate the memory before using the pointers.

**NOTE:** The project maintainers were already aware of this and a fix would be deployed in future.

**Reference:** https://github.com/karpathy/llm.c/blob/3bcb9ba7d2e37f48e4b97806736783acd6da2f41/train_gpt2.c#L892
