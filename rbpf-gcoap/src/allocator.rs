pub mod allocator {
    use alloc::alloc::*;
    use riot_wrappers::riot_sys::malloc;
    use riot_wrappers::riot_sys::free;
    use core::ffi::c_void;

    /// The global allocator type.
    #[derive(Default)]
    pub struct Allocator;

    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            malloc(layout.size() as u32) as *mut u8
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            free(ptr as *mut c_void);
        }
    }


    /// The static global allocator.
    #[global_allocator]
    static GLOBAL_ALLOCATOR: Allocator = Allocator;
}

