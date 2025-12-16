// Add tests for ReturnStack for VecStack
#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use crate::types::stack::BoxStack;
    use crate::types::stack::ReturnStack;
    use crate::types::stack::VecStack;
    #[test]
    fn test_vec_stack() {
        let mut s = VecStack::new(4).unwrap();
        assert_eq!(s.max_depth(), 4);
        s.push(50);
        s.push(44);
        s.push(30);
        s.push(35);
        assert_eq!(s.depth(), 4);
        s.push(24);
        assert_eq!(s.depth(), 4);
        s.pop();
        s.pop();
        assert_eq!(s.depth(), 2);
        s.pop();
        s.pop();
        assert_eq!(s.depth(), 0);
    }

    #[test]
    fn test_vec_stack_overflow() {
        let mut vec_stack = VecStack::new(3).unwrap();
        vec_stack.push(33);
        vec_stack.push(0);
        vec_stack.push(1101);
        vec_stack.push(100); // leaves out 33

        assert_eq!(vec_stack.pop(), Some(100));
        assert_eq!(vec_stack.pop(), Some(1101));
        assert_eq!(vec_stack.pop(), Some(0));
        assert_eq!(vec_stack.pop(), None);
    }

    #[test]
    fn test_box_stack() {
        let mut box_stack = BoxStack::new(4).unwrap();
        assert_eq!(box_stack.max_depth(), 4);
        box_stack.push(34);
        box_stack.push(55);
        assert_eq!(box_stack.depth(), 2);
        box_stack.push(100);
        box_stack.push(2000);
        box_stack.push(640);
        assert_eq!(box_stack.depth(), 4);
        for _i in 0..5 {
            box_stack.pop();
        }
        assert_eq!(box_stack.depth(), 0);
    }

    #[test]
    fn test_box_overflow() {
        let mut box_stack = BoxStack::new(3).unwrap();
        for n in 1..10 {
            box_stack.push(n)
        }

        let mut box_stack_copy = box_stack.clone();
        assert_eq!(box_stack.pop(), Some(9));
        assert_eq!(box_stack.pop(), Some(8));
        assert_eq!(box_stack.pop(), Some(7));
        assert_eq!(box_stack.pop(), None);

        assert_eq!(box_stack_copy.pop(), Some(9));
        assert_eq!(box_stack_copy.depth(), 2)
    }
}
